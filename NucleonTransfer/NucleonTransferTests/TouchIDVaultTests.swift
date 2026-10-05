// Nucleon Transfer — F8.5-V3 "Require Touch ID" (Swift Testing).
// SessionSeal (AES-GCM round trip with a fixed key, tamper/wrong key,
// format marker), SessionVault sealed mode over InMemoryKeychainStore
// (simulated Touch ID: success, cancel, unavailable, enrollment changed),
// re-seal/unseal, token rotation without a prompt, RestoreFailure's
// biometric policy, "Forget This Mac", the live store's query builders
// (access control flags, attributes-only diagnostics query) and the
// diagnostic summary. Offline only — the real keychain is never touched.
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Testing

@testable import NucleonTransfer

private func sample(refresh: String = "refresh-0") -> RememberedSession {
    RememberedSession(
        uid: "uid-0", refreshToken: refresh,
        saltedKeyPass: Data((0..<31).map { UInt8($0) }),
        username: "user@proton.me",
        savedAt: Date(timeIntervalSince1970: 1_790_000_000)
    )
}

private let fixedKey = SymmetricKey(data: Data((0..<32).map { UInt8($0 &* 7) }))
private let reason = "unlock your saved sign-in"

private func makeDefaults() -> UserDefaults {
    let name = "nt.tests.touchid.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: name) ?? .standard
    defaults.removePersistentDomain(forName: name)
    return defaults
}

struct SessionSealTests {
    @Test func roundTripWithFixedKey() throws {
        let plain = Data(#"{"version":1}"#.utf8)
        let sealed = try SessionSeal.seal(plain, key: fixedKey)
        #expect(sealed.starts(with: SessionBlobFormat.sealedMagic))
        #expect(SessionBlobFormat.detect(sealed) == .sealed)
        // magic + 12-byte nonce + ciphertext + 16-byte tag
        #expect(sealed.count == SessionBlobFormat.sealedMagic.count + 12 + plain.count + 16)
        #expect(try SessionSeal.open(sealed, key: fixedKey) == plain)
        // Fresh nonce every time.
        #expect(try SessionSeal.seal(plain, key: fixedKey) != sealed)
    }

    @Test func tamperedCiphertextFails() throws {
        let sealed = try SessionSeal.seal(Data("secret".utf8), key: fixedKey)
        for index in [SessionBlobFormat.sealedMagic.count, sealed.count - 20, sealed.count - 1] {
            var tampered = sealed
            tampered[tampered.startIndex + index] ^= 0x01
            #expect(throws: (any Error).self) { try SessionSeal.open(tampered, key: fixedKey) }
        }
    }

    @Test func wrongKeyFails() throws {
        let sealed = try SessionSeal.seal(Data("secret".utf8), key: fixedKey)
        #expect(throws: (any Error).self) {
            try SessionSeal.open(sealed, key: SymmetricKey(size: .bits256))
        }
    }

    @Test func formatDetection() throws {
        #expect(SessionBlobFormat.detect(Data(#"{"version":1}"#.utf8)) == .plain)
        #expect(SessionBlobFormat.detect(Data("garbage".utf8)) == .unknown)
        #expect(SessionBlobFormat.detect(Data()) == .unknown)
        #expect(SessionBlobFormat.detect(SessionBlobFormat.sealedMagic) == .sealed)
        #expect(throws: SessionSeal.SealError.self) {
            try SessionSeal.open(Data(#"{"version":1}"#.utf8), key: fixedKey)
        }
    }
}

struct TouchIDVaultTests {
    @Test func sealedSaveWritesBiometricKEKAndCiphertext() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample(), sealed: true)

        let kek = try #require(store.raw(SessionVault.kekAccount))
        #expect(kek.count == 32)
        #expect(store.protection(SessionVault.kekAccount) == .biometryCurrentSet)
        let blob = try #require(store.raw(SessionVault.account))
        #expect(store.protection(SessionVault.account) == .standard)
        #expect(SessionBlobFormat.detect(blob) == .sealed)
        #expect(blob.range(of: Data("refresh-0".utf8)) == nil)
        #expect(blob.range(of: Data("user@proton.me".utf8)) == nil)
        #expect(try SessionSeal.open(blob, key: SymmetricKey(data: kek)).first == UInt8(ascii: "{"))
        #expect(store.promptCount == 0)   // writing never prompts
        #expect(await vault.storedFormat() == .sealed)
    }

    @Test func relaunchNeedsTouchIDThenCachesKEK() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)

        let relaunched = SessionVault(store: store)
        #expect(await relaunched.hasRememberedSession())
        #expect(await relaunched.load() == nil)            // no prompt, nothing deleted
        #expect(store.raw(SessionVault.account) != nil)
        #expect(store.promptCount == 0)

        #expect(await relaunched.unlock(reason: reason) == .session(sample()))
        #expect(store.promptCount == 1)
        #expect(await relaunched.unlock(reason: reason) == .session(sample()))
        #expect(await relaunched.load() == sample())
        #expect(store.promptCount == 1)                    // KEK cached for the session
    }

    @Test func tokenRotationReSealsWithoutPrompt() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        let vault = SessionVault(store: store)
        _ = await vault.unlock(reason: reason)
        let before = store.raw(SessionVault.account)

        #expect(try await vault.updateTokens(uid: "uid-1", refreshToken: "refresh-1"))
        #expect(store.promptCount == 1)
        let after = try #require(store.raw(SessionVault.account))
        #expect(after != before)
        #expect(SessionBlobFormat.detect(after) == .sealed)
        #expect(after.range(of: Data("refresh-1".utf8)) == nil)

        let next = SessionVault(store: store)
        guard case let .session(loaded) = await next.unlock(reason: reason) else {
            Issue.record("expected a session")
            return
        }
        #expect(loaded.refreshToken == "refresh-1")
        #expect(loaded.saltedKeyPass == sample().saltedKeyPass)
    }

    @Test func rotationWithoutCachedKEKIsANoOp() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        let blob = store.raw(SessionVault.account)
        let vault = SessionVault(store: store)
        #expect(try await vault.updateTokens(uid: "u", refreshToken: "r") == false)
        #expect(store.raw(SessionVault.account) == blob)
        #expect(store.promptCount == 0)
    }

    @Test(arguments: [
        (InMemoryKeychainStore.Biometry.cancel, BiometricUnlockFailure.cancelled),
        (.unavailable, .unavailable),
    ])
    func cancelOrUnavailableKeepsBothItems(_ behavior: InMemoryKeychainStore.Biometry,
                                           _ expected: BiometricUnlockFailure) async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        store.simulateBiometry(behavior)
        let vault = SessionVault(store: store)
        #expect(await vault.unlock(reason: reason) == .failed(expected))
        #expect(store.raw(SessionVault.account) != nil)
        #expect(store.raw(SessionVault.kekAccount) != nil)
        // Retry after the user cooperates.
        store.simulateBiometry(.succeed)
        #expect(await vault.unlock(reason: reason) == .session(sample()))
    }

    @Test func enrollmentChangeDeletesBothItems() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        store.simulateBiometry(.enrollmentChanged)
        let vault = SessionVault(store: store)
        #expect(await vault.unlock(reason: reason) == .failed(.invalidated))
        #expect(store.raw(SessionVault.account) == nil)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(await vault.hasRememberedSession() == false)
    }

    @Test func missingKEKDeletesBlob() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        try store.delete(account: SessionVault.kekAccount)
        #expect(await SessionVault(store: store).unlock(reason: reason) == .failed(.invalidated))
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func tamperedSealedBlobDeletesBothItems() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        var blob = try #require(store.raw(SessionVault.account))
        blob[blob.index(before: blob.endIndex)] ^= 0xFF
        store.setRaw(blob, for: SessionVault.account)
        #expect(await SessionVault(store: store).unlock(reason: reason) == .failed(.invalidated))
        #expect(store.raw(SessionVault.account) == nil)
        #expect(store.raw(SessionVault.kekAccount) == nil)
    }

    @Test func wrongSizeKEKIsInvalidated() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        try store.set(Data(count: 16), for: SessionVault.kekAccount, protection: .biometryCurrentSet)
        #expect(await SessionVault(store: store).unlock(reason: reason) == .failed(.invalidated))
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func plainItemUnlocksWithoutPrompt() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample())
        #expect(await SessionVault(store: store).unlock(reason: reason) == .session(sample()))
        #expect(store.promptCount == 0)
        #expect(await SessionVault(store: store).unlock(reason: reason) != .absent)
        #expect(await SessionVault(store: InMemoryKeychainStore()).unlock(reason: reason) == .absent)
    }

    @Test func plainSaveDropsKEK() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample(), sealed: true)
        try await vault.save(sample())
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(await vault.storedFormat() == .plain)
    }

    // MARK: Require Touch ID switched

    @Test func turningOnReSealsWithoutPrompt() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        #expect(await vault.setSealed(true, reason: reason))
        #expect(await vault.storedFormat() == .sealed)
        #expect(store.protection(SessionVault.kekAccount) == .biometryCurrentSet)
        #expect(store.promptCount == 0)
        #expect(await vault.load() == sample())            // KEK cached
        #expect(await vault.setSealed(true, reason: reason)) // idempotent
    }

    @Test func turningOffWithCachedKEKUnsealsWithoutPrompt() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample(), sealed: true)
        #expect(await vault.setSealed(false, reason: reason))
        #expect(await vault.storedFormat() == .plain)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(store.promptCount == 0)
        #expect(await SessionVault(store: store).load() == sample())
    }

    @Test func turningOffWithoutKEKPromptsAndCancelRevertsNothing() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        let vault = SessionVault(store: store)
        store.simulateBiometry(.cancel)
        #expect(await vault.setSealed(false, reason: reason) == false)
        #expect(await vault.storedFormat() == .sealed)
        #expect(store.raw(SessionVault.kekAccount) != nil)
        store.simulateBiometry(.succeed)
        #expect(await vault.setSealed(false, reason: reason))
        #expect(await vault.storedFormat() == .plain)
        #expect(store.promptCount == 2)
    }

    @Test func switchingWithNothingRememberedOnlyTracksKEK() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        #expect(await vault.setSealed(true, reason: reason))
        #expect(store.raw(SessionVault.account) == nil)
        try store.set(Data(count: 32), for: SessionVault.kekAccount, protection: .biometryCurrentSet)
        #expect(await vault.setSealed(false, reason: reason))
        #expect(store.raw(SessionVault.kekAccount) == nil)
    }

    @Test func failedSealKeepsPlainSession() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        store.failNext(.write)
        #expect(await vault.setSealed(true, reason: reason) == false)
        #expect(await vault.storedFormat() == .plain)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(await vault.load() == sample())
    }

    // MARK: lock / delete / forget

    @Test func lockDropsCachedKEK() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample(), sealed: true)
        await vault.lock()
        #expect(await vault.load() == nil)
        #expect(store.raw(SessionVault.account) != nil)
        #expect(await vault.unlock(reason: reason) == .session(sample()))
        #expect(store.promptCount == 1)
    }

    @Test func deleteRemovesBothItems() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample(), sealed: true)
        await vault.delete()
        #expect(store.raw(SessionVault.account) == nil)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(await vault.load() == nil)
    }

    @Test func forgetThisMacClearsBothItemsAndUsername() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        let defaults = makeDefaults()
        AppSettings.setLastUsername("user@proton.me", in: defaults)
        defaults.set(true, forKey: AppSettings.keepSignedInKey)
        try await vault.save(sample(), sealed: true)

        await SavedSignIn.forgetThisMac(vault: vault, defaults: defaults)

        #expect(store.raw(SessionVault.account) == nil)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(AppSettings.lastUsername(defaults) == nil)
        // Preferences stay — they're choices, not account data.
        #expect(AppSettings.keepsSignedIn(defaults))
    }

    @Test func failedKEKReadIsUnavailableAndKeeps() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        store.failNext(.biometricRead)
        #expect(await SessionVault(store: store).unlock(reason: reason) == .failed(.unavailable))
        #expect(store.raw(SessionVault.account) != nil)
        #expect(store.raw(SessionVault.kekAccount) != nil)
    }

    @Test func concurrentUnlocksShareOnePrompt() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample(), sealed: true)
        let vault = SessionVault(store: store)
        async let first = vault.unlock(reason: reason)
        async let second = vault.unlock(reason: reason)
        let results = await [first, second]
        #expect(results == [.session(sample()), .session(sample())])
        #expect(store.promptCount == 1)
    }

    /// The prompt suspends the vault (F8.5 review): a delete that lands
    /// while it is up wins — the KEK that arrives afterwards is dropped,
    /// not cached for a later sealed save.
    @Test func itemsChangedDuringPromptDiscardsKEK() async throws {
        let inner = InMemoryKeychainStore()
        try await SessionVault(store: inner).save(sample(), sealed: true)
        let oldKEK = inner.raw(SessionVault.kekAccount)
        let store = GatedBiometricStore(inner: inner)
        let vault = SessionVault(store: store)

        let unlocking = Task { await vault.unlock(reason: reason) }
        await store.waitForPrompt()
        await vault.delete()
        store.release()
        #expect(await unlocking.value == .absent)

        try await vault.save(sample(), sealed: true)
        // No stale KEK was reused: a fresh one was written.
        let newKEK = try #require(inner.raw(SessionVault.kekAccount))
        #expect(newKEK != oldKEK)
    }

    @Test func fakeRefusesSilentReadOfBiometricItem() throws {
        let store = InMemoryKeychainStore()
        try store.set(Data([1]), for: "k", protection: .biometryCurrentSet)
        #expect(throws: KeychainStoreError(status: errSecInteractionNotAllowed)) {
            try store.data(for: "k")
        }
    }
}

struct TouchIDPolicyTests {
    /// F8.5 review: evaluatePolicy first, then the non-interactive read.
    @Test func biometricReadClassification() {
        // Evaluation outcomes decide alone (no read happens).
        for status in [errSecSuccess, errSecAuthFailed, errSecItemNotFound] {
            #expect(BiometricRead.classify(policy: .cancelled, readStatus: status) == .cancelled)
            #expect(BiometricRead.classify(policy: .failed, readStatus: status) == .unavailable)
            #expect(BiometricRead.classify(policy: .notEnrolled, readStatus: status) == .invalidated)
        }
        // A matched finger that the item refuses = the item is void: no
        // "unavailable" retry loop on an invalidated .biometryCurrentSet item.
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecSuccess) == nil)
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecAuthFailed) == .invalidated)
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecItemNotFound) == .invalidated)
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecUserCanceled) == .cancelled)
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecInteractionNotAllowed) == .unavailable)
        #expect(BiometricRead.classify(policy: .succeeded, readStatus: errSecIO) == .unavailable)
    }

    @Test func policyErrorMapping() {
        #expect(BiometricPolicyOutcome.from(.userCancel) == .cancelled)
        #expect(BiometricPolicyOutcome.from(.appCancel) == .cancelled)
        #expect(BiometricPolicyOutcome.from(.systemCancel) == .cancelled)
        #expect(BiometricPolicyOutcome.from(.userFallback) == .cancelled)
        #expect(BiometricPolicyOutcome.from(.biometryNotEnrolled) == .notEnrolled)
        #expect(BiometricPolicyOutcome.from(.biometryLockout) == .failed)
        #expect(BiometricPolicyOutcome.from(.biometryNotAvailable) == .failed)
        #expect(BiometricPolicyOutcome.from(.authenticationFailed) == .failed)
        #expect(BiometricPolicyOutcome.from(.notInteractive) == .failed)
        #expect(BiometricPolicyOutcome.from(error: LAError(.userCancel)) == .cancelled)
        #expect(BiometricPolicyOutcome.from(error: CancellationError()) == .failed)
    }

    @Test func restoreFailureBiometricDecisions() {
        #expect(RestoreFailure.decision(for: BiometricUnlockFailure.cancelled) == .retryTouchID)
        #expect(RestoreFailure.decision(for: BiometricUnlockFailure.unavailable) == .retryTouchID)
        #expect(RestoreFailure.decision(for: BiometricUnlockFailure.invalidated) == .forgetTouchIDChanged)
        #expect(RestoreFailure.keepsRememberedSession(.retryTouchID))
        #expect(RestoreFailure.keepsRememberedSession(.keepAndRetry))
        #expect(!RestoreFailure.keepsRememberedSession(.forgetTouchIDChanged))
        #expect(!RestoreFailure.keepsRememberedSession(.forget))
        let messages: Set<String> = [
            RestoreFailure.message(for: .keepAndRetry), RestoreFailure.message(for: .forget),
            RestoreFailure.message(for: .retryTouchID), RestoreFailure.message(for: .forgetTouchIDChanged),
        ]
        #expect(messages.count == 4)
    }

    @Test func requireTouchIDDefaultsOff() {
        let defaults = makeDefaults()
        #expect(AppSettings.requiresTouchID(defaults) == false)
        defaults.set(true, forKey: AppSettings.requireTouchIDKey)
        #expect(AppSettings.requiresTouchID(defaults))
        AppSettings.setLastUsername("a", in: defaults)
        AppSettings.clearLastUsername(in: defaults)
        #expect(AppSettings.lastUsername(defaults) == nil)
    }
}

struct TouchIDQueryBuilderTests {
    @Test func accessControlFlags() {
        #expect(LiveKeychainStore.accessControlFlags(.standard) == nil)
        #expect(LiveKeychainStore.accessControlFlags(.biometryCurrentSet) == .biometryCurrentSet)
    }

    @Test func biometricAddQueryUsesAccessControlNotAccessible() {
        let add = LiveKeychainStore.addQuery(service: "svc.session", account: "kek",
                                             data: Data([9]), protection: .biometryCurrentSet)
        #expect(add[kSecAttrAccessControl as String] != nil)
        #expect(add[kSecAttrAccessible as String] == nil)
        #expect(add[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(add[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(add[kSecAttrAccount as String] as? String == "kek")
        #expect(add[kSecValueData as String] as? Data == Data([9]))
        #expect(add[kSecAttrAccessGroup as String] == nil)
    }

    @Test func readQueryWithoutContextHasNone() {
        let read = LiveKeychainStore.readQuery(service: "svc", account: "a")
        #expect(read[kSecUseAuthenticationContext as String] == nil)
    }

    @Test func attributesQueryNeverAsksForData() {
        let query = LiveKeychainStore.attributesQuery(service: "svc", account: "a")
        #expect(query[kSecReturnAttributes as String] as? Bool == true)
        #expect(query[kSecReturnData as String] == nil)
        #expect(query[kSecValueData as String] == nil)
        #expect(query[kSecAttrSynchronizable as String] as? String == kSecAttrSynchronizableAny as String)
        #expect(query[kSecMatchLimit as String] as? String == kSecMatchLimitOne as String)
        #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
    }

    @Test func diagnosticSummary() {
        let info = KeychainItemInfo.from(attributes: [
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String,
            kSecAttrSynchronizable as String: NSNumber(value: false),
            kSecValueData as String: Data("secret-token".utf8),   // ignored even if present
        ], status: errSecSuccess)
        #expect(info.exists)
        #expect(info.synchronizable == false)
        #expect(!info.hasAccessControl)
        #expect(info.summary.contains("WhenUnlockedThisDeviceOnly"))
        #expect(info.summary.contains("synchronizable: no"))
        #expect(!info.summary.contains("secret-token"))
        #expect(KeychainItemInfo.missing(status: errSecItemNotFound).summary.contains("exists: no"))
        #expect(KeychainItemInfo.missing(status: errSecInteractionNotAllowed).summary
            .contains("attributes need authentication"))
        #expect(KeychainItemInfo.accessibleName(nil) == "unknown")
        #expect(KeychainItemInfo.accessibleName("xyz") == "xyz")
    }
}

/// Forwards to an InMemoryKeychainStore, but holds each Touch ID read until
/// `release()` — the vault is suspended on the prompt meanwhile.
private final class GatedBiometricStore: KeychainStore {
    private let inner: InMemoryKeychainStore
    private let started: AsyncStream<Void>
    private let startedContinuation: AsyncStream<Void>.Continuation
    private let gate: AsyncStream<Void>
    private let gateContinuation: AsyncStream<Void>.Continuation

    init(inner: InMemoryKeychainStore) {
        self.inner = inner
        (started, startedContinuation) = AsyncStream.makeStream(of: Void.self)
        (gate, gateContinuation) = AsyncStream.makeStream(of: Void.self)
    }

    func waitForPrompt() async {
        for await _ in started { return }
    }

    func release() { gateContinuation.yield() }

    func data(for account: String) throws -> Data? { try inner.data(for: account) }

    func authenticatedData(for account: String, reason: String) async -> Result<Data, BiometricUnlockFailure> {
        startedContinuation.yield()
        for await _ in gate { break }
        return await inner.authenticatedData(for: account, reason: reason)
    }

    func set(_ data: Data, for account: String, protection: KeychainProtection) throws {
        try inner.set(data, for: account, protection: protection)
    }

    func delete(account: String) throws { try inner.delete(account: account) }
}
