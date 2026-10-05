// Nucleon Transfer — F8.5-V2 "Keep me signed in" integration (Swift Testing).
// SessionManager.restore over a fake SessionAuthAPI (success, rejected
// token, network failure), the token observer (refresh / adopt / signOut /
// discard), the refresh body without an access token, the RestoreFailure
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
        let json = #"{"UID":"uid","AccessToken":"access-\#(n)","RefreshToken":"refresh-\#(n)","ServerProof":""}"#
        return try JSONDecoder().decode(ProtonAuth.self, from: Data(json.utf8))
    }

    func authDelete(uid: String, accessToken: String) async throws {
        state.withLock { $0.deletes += 1 }
    }
}

/// Records every observer call in order.
private final class TokenLog: Sendable {
    private let events = Mutex([SessionTokens?]())
    var all: [SessionTokens?] { events.withLock { $0 } }

    func observer() -> @Sendable (SessionTokens?) async -> Void {
        { [self] tokens in events.withLock { $0.append(tokens) } }
    }
}

struct SessionRestoreTests {
    // MARK: SessionManager.restore

    @Test func restoreRefreshesAndAdoptsTheSession() async throws {
        let api = RestoreAuthAPI()
        let manager = SessionManager(authAPI: api)
        let log = TokenLog()
        await manager.setTokenObserver(log.observer())

        try await manager.restore(uid: "uid", refreshToken: "stored-refresh")

        #expect(api.refreshes.map(\.refreshToken) == ["stored-refresh"])
        #expect(api.refreshes.first?.accessToken == nil)
        #expect(await manager.credentials() == ProtonSession(uid: "uid", accessToken: "access-1", refreshToken: "refresh-1"))
        // The rotated token reached the observer (→ vault.updateTokens).
        #expect(log.all == [SessionTokens(uid: "uid", refreshToken: "refresh-1")])
        // withAuth now runs with the fresh access token.
        let token = try await manager.withAuth { _, token in token }
        #expect(token == "access-1")
    }

    @Test func restoreWithRejectedTokenClearsSessionAndThrows() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.api(code: 10013, message: "Invalid refresh token"))
        let manager = SessionManager(authAPI: api)
        let log = TokenLog()
        await manager.setTokenObserver(log.observer())

        await #expect(throws: ProtonAPIError.api(code: 10013, message: "Invalid refresh token")) {
            try await manager.restore(uid: "uid", refreshToken: "dead")
        }
        #expect(await manager.isSignedIn == false)
        #expect(log.all == [nil])
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

    // MARK: token observer

    @Test func observerFiresOnEveryRefreshAndOnSignOut() async throws {
        let api = RestoreAuthAPI()
        let manager = SessionManager(authAPI: api)
        let log = TokenLog()
        await manager.setTokenObserver(log.observer())
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "access-0", refreshToken: "refresh-0"))
        try await manager.refresh()
        try await manager.refresh()
        await manager.signOut()

        #expect(log.all == [
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
        let log = TokenLog()
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "a", refreshToken: "r"))
        await manager.setTokenObserver(log.observer())
        await manager.discard()
        #expect(await manager.isSignedIn == false)
        #expect(api.deleteCount == 0)
        #expect(log.all == [nil])
    }

    @Test func refreshFailureDoesNotNotify() async {
        let api = RestoreAuthAPI(failure: ProtonAPIError.unauthorized)
        let manager = SessionManager(authAPI: api)
        await manager.adopt(ProtonSession(uid: "uid", accessToken: "a", refreshToken: "r"))
        let log = TokenLog()
        await manager.setTokenObserver(log.observer())
        await #expect(throws: ProtonAPIError.unauthorized) { try await manager.refresh() }
        #expect(log.all.isEmpty)
    }

    @Test func tokensDescriptionIsRedacted() {
        let t = SessionTokens(uid: "uid-secret", refreshToken: "refresh-secret")
        for text in [String(describing: t), String(reflecting: t)] {
            #expect(!text.contains("secret"))
        }
    }

    /// Rotation end to end: observer → SessionVault.updateTokens keeps the
    /// stored salted key password and tracks the newest refresh token.
    @Test func observerDrivenRotationUpdatesVault() async throws {
        let store = InMemoryKeychainStore()
        let vault = SessionVault(store: store)
        let salted = Data(repeating: 7, count: 31)
        try await vault.save(RememberedSession(uid: "uid", refreshToken: "stored",
                                               saltedKeyPass: salted, username: "u"))
        let manager = SessionManager(authAPI: RestoreAuthAPI())
        await manager.setTokenObserver { tokens in
            guard let tokens else { return }
            _ = try? await vault.updateTokens(uid: tokens.uid, refreshToken: tokens.refreshToken)
        }
        try await manager.restore(uid: "uid", refreshToken: "stored")
        try await manager.refresh()

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
}

private struct SignatureFailureStub: Error {}
