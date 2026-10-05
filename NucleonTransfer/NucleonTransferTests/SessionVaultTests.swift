// Nucleon Transfer — F8.5-V1 "Keep me signed in" vault (Swift Testing).
// SessionVault over InMemoryKeychainStore: round-trip, schema version,
// token rotation, delete, corrupt data, store failures; plus the live
// store's query dictionaries (pure builders — the keychain is never hit).
import Foundation
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

struct SessionVaultTests {
    @Test func roundTrip() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        #expect(await vault.load() == sample())
        #expect(await vault.hasRememberedSession())
        #expect(store.protection(SessionVault.account) == .standard)
    }

    @Test func absentIsNil() async {
        let vault = SessionVault(store: InMemoryKeychainStore())
        #expect(await vault.load() == nil)
        #expect(await vault.hasRememberedSession() == false)
    }

    @Test func blobNeverCarriesAccessTokenOrPassword() async throws {
        let store = InMemoryKeychainStore()
        try await SessionVault(store: store).save(sample())
        let raw = try #require(store.raw(SessionVault.account))
        let json = try #require(try JSONSerialization.jsonObject(with: raw) as? [String: Any])
        #expect(Set(json.keys) == ["version", "uid", "refreshToken", "saltedKeyPass", "username", "savedAt"])
        #expect(json["version"] as? Int == 1)
    }

    @Test func otherVersionIsAbsentAndDeleted() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        let raw = try #require(store.raw(SessionVault.account))
        var json = try #require(try JSONSerialization.jsonObject(with: raw) as? [String: Any])
        json["version"] = 2
        store.setRaw(try JSONSerialization.data(withJSONObject: json), for: SessionVault.account)

        #expect(await vault.load() == nil)
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func corruptDataIsAbsentAndDeleted() async {
        let store = InMemoryKeychainStore()
        store.setRaw(Data("not json".utf8), for: SessionVault.account)
        let vault = SessionVault(store: store)
        #expect(await vault.load() == nil)
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func missingFieldIsAbsentAndDeleted() async {
        let store = InMemoryKeychainStore()
        store.setRaw(Data(#"{"version":1,"uid":"u"}"#.utf8), for: SessionVault.account)
        #expect(await SessionVault(store: store).load() == nil)
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func updateTokensRotatesRefreshTokenKeepingSaltedPass() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        #expect(try await vault.updateTokens(uid: "uid-1", refreshToken: "refresh-1"))
        let loaded = try #require(await vault.load())
        #expect(loaded.uid == "uid-1")
        #expect(loaded.refreshToken == "refresh-1")
        #expect(loaded.saltedKeyPass == sample().saltedKeyPass)
        #expect(loaded.username == sample().username)
    }

    @Test func updateTokensWithoutItemCreatesNothing() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        #expect(try await vault.updateTokens(uid: "u", refreshToken: "r") == false)
        #expect(store.raw(SessionVault.account) == nil)
    }

    @Test func deleteRemovesItemAndNeverThrows() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        await vault.delete()
        #expect(await vault.load() == nil)
        store.failNext(.delete)
        await vault.delete()   // store failure is swallowed
    }

    @Test func readFailureIsAbsentButSaveFailureThrows() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(sample())
        store.failNext(.read)
        #expect(await vault.load() == nil)
        #expect(store.raw(SessionVault.account) != nil)   // not deleted on a read error
        store.failNext(.write)
        await #expect(throws: KeychainStoreError.self) { try await vault.save(sample()) }
    }

    @Test func descriptionIsRedacted() {
        let s = sample()
        for text in [String(describing: s), String(reflecting: s), "\(s)"] {
            #expect(!text.contains("refresh-0"))
            #expect(!text.contains("uid-0"))
            #expect(!text.contains("user@proton.me"))
        }
    }

    @Test func wipeZeroesSaltedPass() {
        var s = sample()
        s.wipe()
        #expect(s.saltedKeyPass == Data(count: 31))
    }

    // MARK: live store query builders

    @Test func liveQueryCarriesExactProtectionAttributes() throws {
        let add = LiveKeychainStore.addQuery(service: "svc.session", account: "acct",
                                             data: Data([1, 2]), protection: .standard)
        #expect(add[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(add[kSecAttrService as String] as? String == "svc.session")
        #expect(add[kSecAttrAccount as String] as? String == "acct")
        #expect(add[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(add[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(add[kSecAttrAccessible as String] as? String
            == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(add[kSecValueData as String] as? Data == Data([1, 2]))
        #expect(add[kSecAttrAccessControl as String] == nil)

        let read = LiveKeychainStore.readQuery(service: "svc.session", account: "acct")
        #expect(read[kSecUseDataProtectionKeychain as String] as? Bool == true)
        #expect(read[kSecAttrSynchronizable as String] as? Bool == false)
        #expect(read[kSecReturnData as String] as? Bool == true)
        #expect(read[kSecMatchLimit as String] as? String == kSecMatchLimitOne as String)
        #expect(read[kSecValueData as String] == nil)
    }

    @Test func liveServiceIsBundleScoped() {
        #expect(LiveKeychainStore.defaultService.hasSuffix(".session"))
        #expect(LiveKeychainStore().service == LiveKeychainStore.defaultService)
    }
}
