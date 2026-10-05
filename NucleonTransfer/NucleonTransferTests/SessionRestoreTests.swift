// Nucleon Transfer — F8.5-V2 "Keep me signed in" integration (Swift Testing).
// SessionManager.restore over a fake SessionAuthAPI (success, rejected
// token, network failure), the ordered `tokenChanges` stream (refresh /
// adopt / signOut / discard), the refresh body without an access token, the RestoreFailure
// keep-vs-delete policy and the sign-in settings keys. Offline only.
import Foundation
import Synchronization
import Testing

@testable import NucleonTransfer

/// Refresh rotates to "access-N"/"refresh-N" unless `failure` is set.
private final class RestoreAuthAPI: SessionAuthAPI {
    private struct State {
        var refreshes: [AuthRefreshRequest] = []
        var deletes = 0
    }

    private let state = Mutex(State())
    private let failure: (any Error & Sendable)?

    init(failure: (any Error & Sendable)? = nil) {
        self.failure = failure
    }

    var refreshes: [AuthRefreshRequest] { state.withLock { $0.refreshes } }
    var deleteCount: Int { state.withLock { $0.deletes } }

    func authRefresh(_ body: AuthRefreshRequest) async throws -> ProtonAuth {
        let n = state.withLock { s -> Int in
            s.refreshes.append(body)
            return s.refreshes.count
        }
        if let failure { throw failure }
        let json = #"{"UID":"uid","AccessToken":"access-\#(n)","RefreshToken":"refresh-\#(n)"}"#
        return try JSONDecoder().decode(ProtonAuth.self, from: Data(json.utf8))
    }

    func authDelete(uid: String, accessToken: String) async throws {
        state.withLock { $0.deletes += 1 }
    }
}

/// The first `count` events of `manager.tokenChanges`, in order. The
/// stream buffers everything, so this can run after the calls.
private func takeTokens(_ count: Int, from manager: SessionManager) async -> [SessionTokens?] {
    var iterator = manager.tokenChanges.makeAsyncIterator()
    var events: [SessionTokens?] = []
    for _ in 0..<count {
        guard let event = await iterator.next() else { break }
        events.append(event)
    }
    return events
}

struct SessionRestoreTests {
    // MARK: SessionManager.restore

    @Test func restoreRefreshesAndAdoptsTheSession() async throws {
        let api = RestoreAuthAPI()
        let manager = SessionManager(authAPI: api)

        try await manager.restore(uid: "uid", refreshToken: "stored-refresh")

        #expect(api.refreshes.map(\.refreshToken) == ["stored-refresh"])
        #expect(api.refreshes.first?.accessToken == nil)
        #expect(await manager.credentials() == ProtonSession(uid: "uid", accessToken: "access-1", refreshToken: "refresh-1"))
        // The rotated token is on the stream (→ vault.updateTokens), and
        // restore returned without anyone consuming it.
        #expect(await takeTokens(1, from: manager) == [SessionTokens(uid: "uid", refreshToken: "refresh-1")])
        // withAuth now runs with the fresh access token.
        let token = try await manager.withAuth { _, token in token }
        #expect(token == "access-1")
    }

    @Test func restoreWithRejectedTokenClearsSessionAndThrows() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.api(code: 10013, message: "Invalid refresh token"))
        let manager = SessionManager(authAPI: api)

        await #expect(throws: ProtonAPIError.api(code: 10013, message: "Invalid refresh token")) {
            try await manager.restore(uid: "uid", refreshToken: "dead")
        }
        #expect(await manager.isSignedIn == false)
        #expect(await takeTokens(1, from: manager) == [nil])
        #expect(api.deleteCount == 0)   // nothing to revoke: it never had an access token
    }

    @Test func restoreNetworkFailureClearsSessionAndIsTransient() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.transport(URLError(.notConnectedToInternet)))
        let manager = SessionManager(authAPI: api)
        var thrown: (any Error)?
        do {
            try await manager.restore(uid: "uid", refreshToken: "kept")
        } catch {
            thrown = error
        }
        let error = try? #require(thrown)
        #expect(error.map(RestoreFailure.decision(for:)) == .keepAndRetry)
        #expect(await manager.isSignedIn == false)
    }

    @Test func restoreUnauthorizedIsForget() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.unauthorized)
        let manager = SessionManager(authAPI: api)
        await #expect(throws: ProtonAPIError.unauthorized) {
            try await manager.restore(uid: "uid", refreshToken: "dead")
        }
        #expect(RestoreFailure.decision(for: ProtonAPIError.unauthorized) == .forget)
    }

    // MARK: token stream

    @Test func streamCarriesEveryChangeInOrder() async throws {
        let api = RestoreAuthAPI()
        let manager = SessionManager(authAPI: api)
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "access-0", refreshToken: "refresh-0"))
        try await manager.refresh()
        try await manager.refresh()
        await manager.signOut()

        // Nobody consumed while the refreshes ran: the network path never
        // waits for the Keychain writer.
        #expect(await takeTokens(4, from: manager) == [
            SessionTokens(uid: "uid", refreshToken: "refresh-0"),
            SessionTokens(uid: "uid", refreshToken: "refresh-1"),
            SessionTokens(uid: "uid", refreshToken: "refresh-2"),
            nil,
        ])
        #expect(api.deleteCount == 1)
    }

    @Test func discardEndsLocallyWithoutRevoking() async {
        let api = RestoreAuthAPI()
        let manager = SessionManager(authAPI: api)
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "a", refreshToken: "r"))
        await manager.discard()
        #expect(await manager.isSignedIn == false)
        #expect(api.deleteCount == 0)
        #expect(await takeTokens(2, from: manager) == [SessionTokens(uid: "uid", refreshToken: "r"), nil])
    }

    @Test func refreshFailureDoesNotNotify() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.unauthorized)
        let manager = SessionManager(authAPI: api)
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "a", refreshToken: "r"))
        await #expect(throws: ProtonAPIError.unauthorized) { try await manager.refresh() }
        await manager.discard()
        // adopt, then straight to the discard: the failed refresh added nothing.
        #expect(await takeTokens(2, from: manager) == [SessionTokens(uid: "uid", refreshToken: "r"), nil])
    }

    @Test func tokensDescriptionIsRedacted() {
        let t = SessionTokens(uid: "uid-secret", refreshToken: "refresh-secret")
        for text in [String(describing: t), String(reflecting: t)] {
            #expect(!text.contains("secret"))
        }
    }

    /// Rotation end to end: stream → SessionVault.updateTokens keeps the
    /// stored salted key password and tracks the newest refresh token.
    @Test func streamDrivenRotationUpdatesVault() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        let salted = Data(repeating: 7, count: 31)
        try await vault.save(RememberedSession(uid: "uid", refreshToken: "stored",
                                               saltedKeyPass: salted, username: "u"))
        let manager = SessionManager(authAPI: RestoreAuthAPI())
        try await manager.restore(uid: "uid", refreshToken: "stored")
        try await manager.refresh()
        // The consumer applies the events in order, after the fact.
        for case let tokens? in await takeTokens(2, from: manager) {
            try await vault.updateTokens(uid: tokens.uid, refreshToken: tokens.refreshToken)
        }

        let loaded = try #require(await vault.load())
        #expect(loaded.refreshToken == "refresh-2")
        #expect(loaded.saltedKeyPass == salted)
    }

    // MARK: refresh body

    @Test func refreshBodyOmitsAbsentAccessToken() throws {
        let restored = AuthRefreshRequest(uid: "u", refreshToken: "r", state: "s", accessToken: nil)
        let json = try #require(try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(restored)) as? [String: Any])
        #expect(json["AccessToken"] == nil)
        #expect(json["RefreshToken"] as? String == "r")
        #expect(json["GrantType"] as? String == "refresh_token")

        let live = AuthRefreshRequest(uid: "u", refreshToken: "r", state: "s", accessToken: "a")
        let liveJSON = try #require(try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(live)) as? [String: Any])
        #expect(liveJSON["AccessToken"] as? String == "a")
    }

    // MARK: RestoreFailure policy

    @Test(arguments: [
        (ProtonAPIError.transport(URLError(.notConnectedToInternet)), RestoreFailure.Decision.keepAndRetry),
        (ProtonAPIError.transport(URLError(.timedOut)), .keepAndRetry),
        (ProtonAPIError.http(status: 503, code: nil, message: "x"), .keepAndRetry),
        (ProtonAPIError.http(status: 429, code: nil, message: "x"), .keepAndRetry),
        (ProtonAPIError.rateLimited, .keepAndRetry),
        (ProtonAPIError.unauthorized, .forget),
        (ProtonAPIError.api(code: 10013, message: "Invalid refresh token"), .forget),
        (ProtonAPIError.http(status: 422, code: 10013, message: "x"), .forget),
        (ProtonAPIError.http(status: 503, code: 9001, message: "x"), .forget),
        (ProtonAPIError.humanVerificationRequired, .forget),
        (ProtonAPIError.keyVerificationFailed, .forget),
        (ProtonAPIError.transport(DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "x"))), .forget),
    ])
    func restoreFailureDecision(_ error: ProtonAPIError, _ expected: RestoreFailure.Decision) {
        #expect(RestoreFailure.decision(for: error) == expected)
    }

    @Test func rawNetworkAndCancellationAreTransient() {
        #expect(RestoreFailure.decision(for: URLError(.networkConnectionLost)) == .keepAndRetry)
        #expect(RestoreFailure.decision(for: CancellationError()) == .keepAndRetry)
        #expect(RestoreFailure.decision(for: SignatureFailureStub()) == .forget)
    }

    @Test func restoreMessagesAreDistinct() {
        #expect(RestoreFailure.message(for: .keepAndRetry) != RestoreFailure.message(for: .forget))
    }

    // MARK: settings

    @Test func signInSettingsDefaultsAndUsernameTrim() {
        let name = "nt.tests.restore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name) ?? .standard
        defer { defaults.removePersistentDomain(forName: name) }
        #expect(AppSettings.keepsSignedIn(defaults) == false)
        #expect(AppSettings.lastUsername(defaults) == nil)
        AppSettings.setLastUsername("  user@proton.me \n", in: defaults)
        #expect(AppSettings.lastUsername(defaults) == "user@proton.me")
        AppSettings.setLastUsername("   ", in: defaults)
        #expect(AppSettings.lastUsername(defaults) == "user@proton.me")
        defaults.set(true, forKey: AppSettings.keepSignedInKey)
        #expect(AppSettings.keepsSignedIn(defaults))
    }

    /// F8.5 review: the last username follows "Keep me signed in".
    @Test func lastUsernameOnlyWithKeepSignedIn() {
        let name = "nt.tests.restore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name) ?? .standard
        defer { defaults.removePersistentDomain(forName: name) }

        AppSettings.recordSignIn(username: "off@proton.me", in: defaults)
        #expect(AppSettings.lastUsername(defaults) == nil)

        AppSettings.setKeepsSignedIn(true, in: defaults)
        AppSettings.recordSignIn(username: " on@proton.me ", in: defaults)
        #expect(AppSettings.lastUsername(defaults) == "on@proton.me")
        AppSettings.recordSignOut(in: defaults)              // kept while on
        #expect(AppSettings.lastUsername(defaults) == "on@proton.me")

        AppSettings.setKeepsSignedIn(false, in: defaults)
        AppSettings.recordSignOut(in: defaults)              // cleared while off
        #expect(AppSettings.lastUsername(defaults) == nil)

        AppSettings.setLastUsername("stale@proton.me", in: defaults)
        AppSettings.recordSignIn(username: "next@proton.me", in: defaults)
        #expect(AppSettings.lastUsername(defaults) == nil)  // off: an old one goes too
    }

    // MARK: keep-signed-in gate (F8.5 review)

    @Test func restoreGateDeletesItemWhenPreferenceIsOff() async throws {
        let name = "nt.tests.restore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name) ?? .standard
        defer { defaults.removePersistentDomain(forName: name) }
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        try await vault.save(RememberedSession(uid: "u", refreshToken: "r",
                                               saltedKeyPass: Data([1]), username: "u"), sealed: true)

        defaults.set(true, forKey: AppSettings.keepSignedInKey)
        #expect(await SavedSignIn.mayRestore(vault: vault, defaults: defaults))
        #expect(await vault.hasRememberedSession())

        defaults.set(false, forKey: AppSettings.keepSignedInKey)
        #expect(await SavedSignIn.mayRestore(vault: vault, defaults: defaults) == false)
        #expect(await vault.hasRememberedSession() == false)
        #expect(store.raw(SessionVault.kekAccount) == nil)
        #expect(store.promptCount == 0)
    }

    @Test func setKeepSignedInWritesPreferenceAndDeletesWhenOff() async throws {
        let name = "nt.tests.restore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name) ?? .standard
        defer { defaults.removePersistentDomain(forName: name) }
        let vault = SessionVault(store: InMemoryKeychainStore())
        let session = RememberedSession(uid: "u", refreshToken: "r", saltedKeyPass: Data([1]), username: "u")

        await SavedSignIn.setKeepSignedIn(true, vault: vault, defaults: defaults)
        #expect(AppSettings.keepsSignedIn(defaults))
        try await vault.save(session)
        await SavedSignIn.setKeepSignedIn(true, vault: vault, defaults: defaults)
        #expect(await vault.hasRememberedSession())          // on never deletes

        await SavedSignIn.setKeepSignedIn(false, vault: vault, defaults: defaults)
        #expect(AppSettings.keepsSignedIn(defaults) == false)
        #expect(await vault.hasRememberedSession() == false)
    }
}

private struct SignatureFailureStub: Error {}

/// F8.5 live check regression: Proton's `/auth/v4/refresh` answer has no
/// `ServerProof` (login-only). A required field made every refresh fail
/// to decode, surfaced as `.api(code: 1000)` → restore deleted the item.
struct RefreshResponseShapeTests {
    @Test func refreshAnswerWithoutServerProofDecodes() throws {
        let json = #"{"Code":1000,"UID":"uid-1","AccessToken":"acc","RefreshToken":"ref","TokenType":"Bearer","Scopes":["full","self"],"ExpiresIn":86400}"#
        let auth = try JSONDecoder().decode(AuthResponse.self, from: Data(json.utf8)).auth
        #expect(auth.uid == "uid-1")
        #expect(auth.refreshToken == "ref")
        #expect(auth.serverProof == nil)
    }
}
