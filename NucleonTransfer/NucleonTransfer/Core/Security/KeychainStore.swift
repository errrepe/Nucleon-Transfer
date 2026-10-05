// Nucleon Transfer — minimal generic-password Keychain seam (F8.5-V1).
// `KeychainStore` is the only thing SessionVault talks to: production uses
// `LiveKeychainStore` (data-protection keychain, this device only, never
// synced); tests use `InMemoryKeychainStore`. Errors carry the OSStatus
// only — never the account's data.
import Foundation
import Security
import Synchronization

/// How a stored item is protected. Only `.standard` exists today; the
/// Touch ID slice adds an access-controlled case (`SecAccessControl` with
/// `.biometryCurrentSet`) that `LiveKeychainStore.addQuery` maps to
/// `kSecAttrAccessControl` instead of `kSecAttrAccessible`.
enum KeychainProtection: Sendable, Equatable {
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no user presence.
    case standard
}

/// Get/set/delete opaque `Data` by account key under one service.
protocol KeychainStore: Sendable {
    /// The stored bytes, or nil when no item exists.
    func data(for account: String) throws -> Data?
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

/// SecItem generic passwords in the data-protection keychain.
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

    /// Protection attributes for a new or updated item.
    static func protectionAttributes(_ protection: KeychainProtection) -> [String: Any] {
        switch protection {
        case .standard:
            return [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        }
    }

    /// Full SecItemAdd dictionary: identity + protection + value.
    static func addQuery(service: String, account: String, data: Data,
                         protection: KeychainProtection) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query.merge(protectionAttributes(protection)) { _, new in new }
        query[kSecValueData as String] = data
        return query
    }

    /// SecItemCopyMatching dictionary for one item's data.
    static func readQuery(service: String, account: String) -> [String: Any] {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return query
    }

    // MARK: KeychainStore

    func data(for account: String) throws -> Data? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            Self.readQuery(service: service, account: account) as CFDictionary, &result
        )
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

    func set(_ data: Data, for account: String, protection: KeychainProtection) throws {
        var update = Self.protectionAttributes(protection)
        update[kSecValueData as String] = data
        let status = SecItemUpdate(
            Self.baseQuery(service: service, account: account) as CFDictionary,
            update as CFDictionary
        )
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            let added = SecItemAdd(
                Self.addQuery(service: service, account: account, data: data,
                              protection: protection) as CFDictionary,
                nil
            )
            guard added == errSecSuccess else { throw KeychainStoreError(status: added) }
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
}

#if DEBUG
/// Test/preview store: a dictionary behind a Mutex. `failNext` makes the
/// next call of that kind throw, to exercise SessionVault's error paths.
final class InMemoryKeychainStore: KeychainStore {
    enum Operation: Sendable { case read, write, delete }

    private struct State {
        var items: [String: Data] = [:]
        var protections: [String: KeychainProtection] = [:]
        var failing: Set<Operation> = []
    }

    private let state = Mutex(State())

    init() {}

    /// Raw bytes of an item (tests corrupt / inspect them).
    func raw(_ account: String) -> Data? { state.withLock { $0.items[account] } }
    func setRaw(_ data: Data?, for account: String) { state.withLock { $0.items[account] = data } }
    func protection(_ account: String) -> KeychainProtection? { state.withLock { $0.protections[account] } }
    func failNext(_ op: Operation) { state.withLock { _ = $0.failing.insert(op) } }

    private func check(_ op: Operation) throws {
        let fail = state.withLock { $0.failing.remove(op) != nil }
        if fail { throw KeychainStoreError(status: errSecIO) }
    }

    func data(for account: String) throws -> Data? {
        try check(.read)
        return state.withLock { $0.items[account] }
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
