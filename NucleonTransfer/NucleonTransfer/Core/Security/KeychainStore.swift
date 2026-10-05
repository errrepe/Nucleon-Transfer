// Nucleon Transfer — minimal generic-password Keychain seam (F8.5-V1/V3).
// `KeychainStore` is the only thing SessionVault talks to: production uses
// `LiveKeychainStore` (data-protection keychain, this device only, never
// synced); tests use `InMemoryKeychainStore`. Errors carry the OSStatus
// only — never the account's data.
// F8.5-V3 adds a Touch ID protected item kind (`SecAccessControl` with
// `.biometryCurrentSet`) and the one read that may show the Touch ID
// prompt (`authenticatedData`). LocalAuthentication is imported here — a
// non-UI system framework, like Security — because the live read needs an
// LAContext; everything above the live calls is a pure, tested builder.
// F8.5 review: that read is async and two-step — `LAContext.evaluatePolicy`
// first (awaited off the caller's actor, so the prompt never blocks a
// thread), then a non-interactive SecItemCopyMatching with the
// authenticated context. `BiometricRead.classify` maps the pair of
// outcomes; errSecAuthFailed AFTER a successful evaluation means the item
// itself is void (fingerprints changed), so it can't loop as "retry".
import Foundation
import LocalAuthentication
import Security
import Synchronization

/// How a stored item is protected.
enum KeychainProtection: Sendable, Equatable {
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no user presence.
    case standard
    /// `SecAccessControl(WhenUnlockedThisDeviceOnly, .biometryCurrentSet)`:
    /// reading needs Touch ID with a currently enrolled finger; adding or
    /// removing a fingerprint invalidates the item for good. No passcode
    /// fallback (that would turn "Touch ID" into "Mac password").
    case biometryCurrentSet
}

/// Why a Touch ID protected read produced nothing usable (F8.5-V3).
enum BiometricUnlockFailure: Error, Sendable, Equatable {
    /// The user dismissed the Touch ID prompt — keep everything, offer retry.
    case cancelled
    /// Touch ID can't be used right now (lid closed, locked out after
    /// failed attempts, no interaction possible) — keep, offer retry.
    case unavailable
    /// The protected item is gone: the enrolled fingerprints changed
    /// (`.biometryCurrentSet` invalidation) or it was deleted — or what it
    /// protects no longer opens. Nothing can recover it: delete.
    case invalidated
}

/// What `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
/// answered, before any Keychain read (F8.5 review).
enum BiometricPolicyOutcome: Sendable, Equatable {
    /// A currently enrolled finger matched.
    case succeeded
    /// The prompt was dismissed (user, app or system cancel, or the
    /// fallback button).
    case cancelled
    /// No fingerprint is enrolled any more: every `.biometryCurrentSet`
    /// item is already void.
    case notEnrolled
    /// No match, lockout, no sensor reachable, no UI possible, or any
    /// other evaluation error — "not now".
    case failed

    static func from(_ code: LAError.Code) -> BiometricPolicyOutcome {
        switch code {
        case .userCancel, .appCancel, .systemCancel, .userFallback: return .cancelled
        case .biometryNotEnrolled: return .notEnrolled
        default: return .failed
        }
    }

    /// An evaluatePolicy error (an LAError, or anything else = `.failed`).
    static func from(error: any Error) -> BiometricPolicyOutcome {
        guard let la = error as? LAError else { return .failed }
        return from(la.code)
    }
}

/// Classification of the two-step Touch ID read (pure, unit-tested).
enum BiometricRead {
    /// nil = success (the KEK bytes are usable). `readStatus` is the
    /// SecItemCopyMatching status of the non-interactive read made with
    /// the authenticated context; it only matters when the policy
    /// evaluation succeeded (otherwise no read happens).
    /// - evaluation cancelled → `.cancelled` (keep, offer retry);
    /// - no finger enrolled → `.invalidated`;
    /// - other evaluation failure / lockout → `.unavailable` (keep);
    /// - evaluation succeeded, then errSecItemNotFound or errSecAuthFailed
    ///   → `.invalidated`: the finger matched but the item refuses it —
    ///   its `.biometryCurrentSet` snapshot no longer exists;
    /// - evaluation succeeded, then errSecUserCanceled → `.cancelled`;
    ///   any other read error → `.unavailable`.
    static func classify(policy: BiometricPolicyOutcome, readStatus: OSStatus) -> BiometricUnlockFailure? {
        switch policy {
        case .cancelled: return .cancelled
        case .notEnrolled: return .invalidated
        case .failed: return .unavailable
        case .succeeded:
            switch readStatus {
            case errSecSuccess: return nil
            case errSecItemNotFound, errSecAuthFailed: return .invalidated
            case errSecUserCanceled: return .cancelled
            default: return .unavailable
            }
        }
    }
}

/// Get/set/delete opaque `Data` by account key under one service.
protocol KeychainStore: Sendable {
    /// The stored bytes, or nil when no item exists. Never shows UI: a
    /// Touch ID protected item fails (see `authenticatedData`).
    func data(for account: String) throws -> Data?
    /// Reads a `.biometryCurrentSet` item behind the Touch ID prompt
    /// (`reason`): evaluates the policy first — suspending, never blocking
    /// a thread — then reads without UI using that authentication.
    /// Failures are already classified (`BiometricRead.classify`).
    func authenticatedData(for account: String, reason: String) async -> Result<Data, BiometricUnlockFailure>
    /// Update-or-add semantics.
    func set(_ data: Data, for account: String, protection: KeychainProtection) throws
    /// Removes the item; a missing item is not an error.
    func delete(account: String) throws
}

/// A Keychain call failed with this status (no payload, no account data).
struct KeychainStoreError: Error, Sendable, Equatable, CustomStringConvertible {
    var status: OSStatus
    var description: String { "Keychain error \(status)" }
}

/// Whether this Mac can use Touch ID now (Settings toggle, sign-in save).
/// False on Macs without a sensor, with no enrolled finger, with the lid
/// closed, or after a lockout.
enum BiometryAvailability {
    static func isAvailable() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
}

/// Non-secret metadata of one item (DEBUG "Check Saved Sign-In").
struct KeychainItemInfo: Sendable, Equatable {
    var exists: Bool
    /// The kSecAttrAccessible value (e.g. "ak", "aku"), when readable.
    var accessible: String?
    var synchronizable: Bool?
    var hasAccessControl: Bool
    /// SecItemCopyMatching status (errSecInteractionNotAllowed = the item
    /// exists but its attributes need authentication).
    var status: OSStatus

    /// Builds the summary from a kSecReturnAttributes dictionary — never
    /// looks at kSecValueData (the query doesn't request it anyway).
    static func from(attributes: [String: Any], status: OSStatus) -> KeychainItemInfo {
        let sync: Bool? = (attributes[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue
        return KeychainItemInfo(
            exists: true,
            accessible: attributes[kSecAttrAccessible as String] as? String,
            synchronizable: sync,
            hasAccessControl: attributes[kSecAttrAccessControl as String] != nil,
            status: status
        )
    }

    static func missing(status: OSStatus) -> KeychainItemInfo {
        KeychainItemInfo(exists: false, accessible: nil, synchronizable: nil,
                         hasAccessControl: false, status: status)
    }

    /// One line per field — status codes and attribute names only.
    var summary: String {
        guard exists || status == errSecInteractionNotAllowed else {
            return "exists: no (status \(status))"
        }
        if !exists {
            return "exists: yes (attributes need authentication, status \(status))"
        }
        let sync = synchronizable.map { $0 ? "yes" : "no" } ?? "unknown"
        return """
        exists: yes
        accessible: \(Self.accessibleName(accessible))
        synchronizable: \(sync)
        access control: \(hasAccessControl ? "yes" : "no")
        """
    }

    static func accessibleName(_ raw: String?) -> String {
        guard let raw else { return "unknown" }
        let names: [(CFString, String)] = [
            (kSecAttrAccessibleWhenUnlockedThisDeviceOnly, "WhenUnlockedThisDeviceOnly"),
            (kSecAttrAccessibleWhenUnlocked, "WhenUnlocked"),
            (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, "AfterFirstUnlockThisDeviceOnly"),
            (kSecAttrAccessibleAfterFirstUnlock, "AfterFirstUnlock"),
            (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, "WhenPasscodeSetThisDeviceOnly"),
        ]
        return names.first { ($0.0 as String) == raw }?.1 ?? raw
    }
}

/// SecItem generic passwords in the data-protection keychain.
/// No kSecAttrAccessGroup: the app has exactly one keychain access group
/// (`$(AppIdentifierPrefix)dev.nucleon.NucleonTransfer`, entitlements), and
/// SecItemAdd defaults to the first group listed — naming it here would
/// only duplicate the team prefix in code.
struct LiveKeychainStore: KeychainStore {
    let service: String

    /// `<bundle id>.session` — the bundle id falls back to the project's
    /// identifier for contexts without a main bundle id (SPM tests).
    static var defaultService: String {
        (Bundle.main.bundleIdentifier ?? "dev.nucleon.NucleonTransfer") + ".session"
    }

    init(service: String = LiveKeychainStore.defaultService) {
        self.service = service
    }

    // MARK: query builders (pure — unit-tested without touching the keychain)

    /// Identifies the item: class, service, account, data-protection
    /// keychain, never synchronizable.
    static func baseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
    }

    /// SecAccessControl flags of a protection level (nil = no access
    /// control object, plain kSecAttrAccessible).
    static func accessControlFlags(_ protection: KeychainProtection) -> SecAccessControlCreateFlags? {
        switch protection {
        case .standard: return nil
        case .biometryCurrentSet: return .biometryCurrentSet
        }
    }

    /// Protection attributes for a new or updated item. The two keys are
    /// mutually exclusive: an access-controlled item carries its
    /// accessibility inside the SecAccessControl. Empty only if
    /// SecAccessControlCreateWithFlags failed — `set` refuses that.
    static func protectionAttributes(_ protection: KeychainProtection) -> [String: Any] {
        guard let flags = accessControlFlags(protection) else {
            return [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil
        ) else { return [:] }
        return [kSecAttrAccessControl as String: access]
    }

    /// Full SecItemAdd dictionary: identity + protection + value.
    static func addQuery(service: String, account: String, data: Data,
                         protection: KeychainProtection) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query.merge(protectionAttributes(protection)) { _, new in new }
        query[kSecValueData as String] = data
        return query
    }

    /// SecItemCopyMatching dictionary for one item's data. `context`
    /// (an LAContext) carries the Touch ID prompt text, or forbids UI.
    static func readQuery(service: String, account: String,
                          context: LAContext? = nil) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { query[kSecUseAuthenticationContext as String] = context }
        return query
    }

    /// Attributes only — NEVER kSecReturnData — and synchronizable "any",
    /// so a stray synced copy would show up too. Used by the DEBUG check.
    static func attributesQuery(service: String, account: String,
                                context: LAContext? = nil) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { query[kSecUseAuthenticationContext as String] = context }
        return query
    }

    // MARK: KeychainStore

    func data(for account: String) throws -> Data? {
        // No UI ever: a Touch ID item fails with errSecInteractionNotAllowed.
        let context = LAContext()
        context.interactionNotAllowed = true
        return try copyData(Self.readQuery(service: service, account: account, context: context))
    }

    func authenticatedData(for account: String, reason: String) async -> Result<Data, BiometricUnlockFailure> {
        await Self.authenticatedRead(service: service, account: account, reason: reason)
    }

    func set(_ data: Data, for account: String, protection: KeychainProtection) throws {
        let attributes = Self.protectionAttributes(protection)
        guard !attributes.isEmpty else { throw KeychainStoreError(status: errSecParam) }
        if protection != .standard {
            // Access control can't be changed in place: replace the item.
            try delete(account: account)
            try add(data, for: account, protection: protection)
            return
        }
        var update = attributes
        update[kSecValueData as String] = data
        let status = SecItemUpdate(
            Self.baseQuery(service: service, account: account) as CFDictionary,
            update as CFDictionary
        )
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            try add(data, for: account, protection: protection)
        default:
            throw KeychainStoreError(status: status)
        }
    }

    func delete(account: String) throws {
        let status = SecItemDelete(Self.baseQuery(service: service, account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError(status: status)
        }
    }

    /// Attribute summary of one item without its data and without UI
    /// (DEBUG diagnostics). Never throws: the status is part of the answer.
    func inspect(account: String) -> KeychainItemInfo {
        let context = LAContext()
        context.interactionNotAllowed = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            Self.attributesQuery(service: service, account: account, context: context) as CFDictionary,
            &result
        )
        guard status == errSecSuccess, let attributes = result as? [String: Any] else {
            return .missing(status: status)
        }
        return .from(attributes: attributes, status: status)
    }

    // MARK: internals

    /// The two-step Touch ID read, `@concurrent` so neither the prompt nor
    /// the Keychain call runs on the caller's actor (SessionVault). The
    /// LAContext is created, evaluated and used here only — one task,
    /// strictly in sequence — so it never crosses an isolation boundary.
    @concurrent
    private static func authenticatedRead(service: String, account: String,
                                          reason: String) async -> Result<Data, BiometricUnlockFailure> {
        let context = LAContext()
        // No "Use Password…" button: Touch ID or nothing (ADR-004).
        context.localizedFallbackTitle = ""
        let policy: BiometricPolicyOutcome
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                                      localizedReason: reason)
            policy = ok ? .succeeded : .failed
        } catch {
            policy = .from(error: error)
        }
        guard policy == .succeeded else {
            return .failure(BiometricRead.classify(policy: policy, readStatus: errSecSuccess) ?? .unavailable)
        }
        // Reuse the evaluated authentication; never a second prompt.
        context.interactionNotAllowed = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            readQuery(service: service, account: account, context: context) as CFDictionary, &result
        )
        if let failure = BiometricRead.classify(policy: .succeeded, readStatus: status) {
            return .failure(failure)
        }
        guard let data = result as? Data else { return .failure(.invalidated) }
        return .success(data)
    }

    private func copyData(_ query: [String: Any]) throws -> Data? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw KeychainStoreError(status: errSecDecode) }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainStoreError(status: status)
        }
    }

    private func add(_ data: Data, for account: String, protection: KeychainProtection) throws {
        let added = SecItemAdd(
            Self.addQuery(service: service, account: account, data: data,
                          protection: protection) as CFDictionary,
            nil
        )
        guard added == errSecSuccess else { throw KeychainStoreError(status: added) }
    }
}

#if DEBUG
/// Test/preview store: a dictionary behind a Mutex. `failNext` makes the
/// next call of that kind throw, to exercise SessionVault's error paths.
/// `.biometryCurrentSet` items behave like the real ones: `data(for:)`
/// refuses them, `authenticatedData` answers per `biometry` (success,
/// user cancelled, unavailable, or "fingerprints changed" — the finger
/// matches but the item answers errSecAuthFailed and is dropped, as the
/// system does) through the same `BiometricRead.classify` as the live
/// store. A failing `.biometricRead` is a matched finger + errSecIO.
final class InMemoryKeychainStore: KeychainStore {
    /// `biometricRead` = the Touch ID read only (`authenticatedData`).
    enum Operation: Sendable { case read, write, delete, biometricRead }

    /// What the next Touch ID prompts do.
    enum Biometry: Sendable { case succeed, cancel, unavailable, enrollmentChanged }

    private struct State {
        var items: [String: Data] = [:]
        var protections: [String: KeychainProtection] = [:]
        var failing: Set<Operation> = []
        var biometry: Biometry = .succeed
        var prompts = 0
    }

    private let state = Mutex(State())

    init() {}

    /// Raw bytes of an item (tests corrupt / inspect them).
    func raw(_ account: String) -> Data? { state.withLock { $0.items[account] } }
    func setRaw(_ data: Data?, for account: String) { state.withLock { $0.items[account] = data } }
    func protection(_ account: String) -> KeychainProtection? { state.withLock { $0.protections[account] } }
    func failNext(_ op: Operation) { state.withLock { _ = $0.failing.insert(op) } }
    func simulateBiometry(_ behavior: Biometry) { state.withLock { $0.biometry = behavior } }
    /// How many Touch ID prompts were shown.
    var promptCount: Int { state.withLock { $0.prompts } }

    private func check(_ op: Operation) throws {
        let fail = state.withLock { $0.failing.remove(op) != nil }
        if fail { throw KeychainStoreError(status: errSecIO) }
    }

    func data(for account: String) throws -> Data? {
        try check(.read)
        return try state.withLock { s in
            if s.protections[account] == .biometryCurrentSet {
                throw KeychainStoreError(status: errSecInteractionNotAllowed)
            }
            return s.items[account]
        }
    }

    func authenticatedData(for account: String, reason: String) async -> Result<Data, BiometricUnlockFailure> {
        let failRead = state.withLock { $0.failing.remove(.biometricRead) != nil }
        let (policy, status, data): (BiometricPolicyOutcome, OSStatus, Data?) = state.withLock { s in
            s.prompts += 1
            switch s.biometry {
            case .succeed:
                if failRead { return (.succeeded, errSecIO, nil) }
                guard let item = s.items[account] else { return (.succeeded, errSecItemNotFound, nil) }
                return (.succeeded, errSecSuccess, item)
            case .cancel:
                return (.cancelled, errSecSuccess, nil)
            case .unavailable:
                return (.failed, errSecSuccess, nil)
            case .enrollmentChanged:
                if s.protections[account] == .biometryCurrentSet {
                    s.items[account] = nil
                    s.protections[account] = nil
                }
                return (.succeeded, errSecAuthFailed, nil)
            }
        }
        if let failure = BiometricRead.classify(policy: policy, readStatus: status) {
            return .failure(failure)
        }
        guard let data else { return .failure(.invalidated) }
        return .success(data)
    }

    func set(_ data: Data, for account: String, protection: KeychainProtection) throws {
        try check(.write)
        state.withLock {
            $0.items[account] = data
            $0.protections[account] = protection
        }
    }

    func delete(account: String) throws {
        try check(.delete)
        state.withLock {
            $0.items[account] = nil
            $0.protections[account] = nil
        }
    }
}
#endif
