// Nucleon Transfer — session orchestrator (memory only, like the official
// Proton Drive app: no Keychain, no disk persistence; re-login each launch).
// Flow: info -> hashPassword(v4, bcrypt) -> SRP proofs -> /auth/v4
//       -> verify serverProof -> optional 2FA.
// 401 anywhere -> one shared (single-flight) /auth/v4/refresh, then retry
// (mirrors go-proton-api Client.doRes).
import CryptoKit
import Foundation

/// In-memory session. Tokens never touch disk; unlocked key seeds never
/// leave their owning actor either (see KeyringCache).
struct ProtonSession: Codable, Sendable, Equatable {
    var uid: String
    var accessToken: String
    var refreshToken: String
}

/// The two session-lifecycle calls `SessionManager` makes outside login.
/// A protocol only so tests can count refreshes and hold one in flight;
/// production uses `APIClient`.
protocol SessionAuthAPI: Sendable {
    func authRefresh(_ body: AuthRefreshRequest) async throws -> ProtonAuth
    func authDelete(uid: String, accessToken: String) async throws
}

extension APIClient: SessionAuthAPI {}

actor SessionManager {
    private var session: ProtonSession?
    private let api: APIClient
    private let authAPI: any SessionAuthAPI
    private let bcrypt: any BcryptHasher
    /// Bumped whenever the session is replaced (login, adopt, signOut). A
    /// refresh that started under an older epoch discards its result, so a
    /// signed-out session can never be written back.
    private var epoch: UInt64 = 0
    /// The one refresh in flight (single-flight): Proton rotates refresh
    /// tokens, so a second concurrent refresh with the same token would fail
    /// and token reuse can revoke the whole session.
    private var refreshTask: Task<ProtonSession, Error>?

    init(api: APIClient = APIClient(), bcrypt: any BcryptHasher = ProtonBcryptHasher(),
         authAPI: (any SessionAuthAPI)? = nil) {
        self.api = api
        self.authAPI = authAPI ?? api
        self.bcrypt = bcrypt
    }

    var isSignedIn: Bool { session != nil }
    var uid: String? { session?.uid }

    /// Current tokens for authed API calls (nil when signed out).
    func credentials() -> ProtonSession? { session }

    /// Runs `op` with (uid, accessToken), refreshing once on 401 and retrying
    /// (mirrors go-proton-api Client.doRes). Concurrent 401s share a single
    /// refresh; if the token that failed was already rotated by another
    /// caller, the retry uses the current token without refreshing again.
    func withAuth<T: Sendable>(_ op: @Sendable (String, String) async throws -> T) async throws -> T {
        guard let creds = session else { throw ProtonAPIError.unauthorized }
        do {
            return try await op(creds.uid, creds.accessToken)
        } catch let e as ProtonAPIError where e == .unauthorized {
            if let current = session, current.accessToken != creds.accessToken {
                return try await op(current.uid, current.accessToken)
            }
            try await refresh()
            guard let retry = session else { throw ProtonAPIError.unauthorized }
            return try await op(retry.uid, retry.accessToken)
        }
    }

    /// Installs an already-established session (tests; the F8.5 restore
    /// path builds on it). Counts as a session replacement.
    func adopt(_ next: ProtonSession) {
        replaceSession(with: next)
    }

    /// Key salts for mailbox unlocking. Requires password-granted scope, i.e.
    /// callable only shortly after a password login (server rejects otherwise).
    func fetchSalts() async throws -> [KeySaltEntry] {
        try await withAuth { uid, token in
            try await self.api.get(KeySaltsResponse.self, path: "/core/v4/keys/salts", uid: uid, accessToken: token).keySalts
        }
    }

    /// Derives the salted key password for `password` (rclone SaltForKey
    /// semantics). Password-equivalent: memory only, never persisted/logged.
    /// Call right after login (key salts require password scope).
    func fetchSaltedKeyPass(password: Data, primaryKeyID: String) async throws -> Data {
        let salts = try await fetchSalts()
        guard let entry = salts.first(where: { $0.id == primaryKeyID }),
              let saltB64 = entry.keySalt,
              let saltBytes = Data(base64Encoded: saltB64) else {
            throw ProtonAPIError.srpParamsOutOfBounds("no key salt for \(primaryKeyID)")
        }
        return try MailboxPassword.salted(keyPass: password, keySalt: saltBytes, hasher: bcrypt)
    }

    /// Login with username + password. Throws needs2FA when TOTP required —
    /// caller must invoke submit2FA(code:) to complete.
    func login(username: String, password: Data) async throws {
        let info = try await api.authInfo(username: username)
        // Modulus arrives PGP-clearsigned; verified against Proton's pinned
        // SRP key (go-srp readClearSignedMessage) before any use.
        let modulus = try ModulusDecoder.decode(info.modulus)
        guard let salt = Data(base64Encoded: info.salt),
              let serverEphem = Data(base64Encoded: info.serverEphemeral) else {
            throw ProtonAPIError.srpParamsOutOfBounds("auth/info not base64")
        }
        var hashed = try PasswordHash.hash(version: info.version, password: password,
                                           username: username, salt: salt,
                                           modulus: modulus, bcrypt: bcrypt)
        defer { SecureBytes.wipe(&hashed) }   // password-equivalent (F8.1-S7)
        let proofs = try SRPClient.generateProofs(hashedPassword: hashed,
                                                 serverEphemeral: serverEphem,
                                                 modulus: modulus)
        let res = try await api.auth(AuthRequest(username: username,
                                                 clientEphemeral: proofs.clientEphemeral.base64EncodedString(),
                                                 clientProof: proofs.clientProof.base64EncodedString(),
                                                 srpSession: info.srpSession))
        guard let serverProof = Data(base64Encoded: res.auth.serverProof) else {
            throw ProtonAPIError.invalidServerProof
        }
        guard constantTimeEquals(serverProof, proofs.expectedServerProof) else {
            throw ProtonAPIError.invalidServerProof
        }
        replaceSession(with: ProtonSession(uid: res.auth.uid, accessToken: res.auth.accessToken,
                                           refreshToken: res.auth.refreshToken))
        if res.auth.requires2FA { throw ProtonAPIError.needs2FA }
    }

    func submit2FA(code: String) async throws {
        guard let s = session else { throw ProtonAPIError.unauthorized }
        try await api.auth2FA(code: code, uid: s.uid, accessToken: s.accessToken)
    }

    /// Ends the session: best-effort server-side logout (DELETE /auth/v4,
    /// go-proton-api auth.go `Client.AuthDelete`) while the token is still
    /// held, then local clear. API failures are ignored — local sign-out
    /// always wins. Any in-flight refresh is cancelled and, via the epoch,
    /// can no longer write its result back.
    func signOut() async {
        let s = session
        replaceSession(with: nil)
        if let s {
            try? await authAPI.authDelete(uid: s.uid, accessToken: s.accessToken)
        }
    }

    /// Refreshes the tokens (POST /auth/v4/refresh). Single-flight: callers
    /// arriving while a refresh is in flight join it instead of sending the
    /// (already spent) refresh token again.
    func refresh() async throws {
        if let inFlight = refreshTask {
            _ = try await inFlight.value
            return
        }
        guard let s = session else { throw ProtonAPIError.unauthorized }
        let started = epoch
        let task = Task { try await self.performRefresh(from: s, epoch: started) }
        refreshTask = task
        _ = try await task.value
    }

    private func performRefresh(from s: ProtonSession, epoch started: UInt64) async throws -> ProtonSession {
        defer { if epoch == started { refreshTask = nil } }
        let state = try SecureRandom.bytes(32)
        let body = AuthRefreshRequest(uid: s.uid, refreshToken: s.refreshToken,
                                      state: state.base64EncodedString(), accessToken: s.accessToken)
        let auth = try await authAPI.authRefresh(body)
        // Signed out (or re-logged in) while the request was in flight: the
        // result belongs to a session that no longer exists.
        guard epoch == started else { throw ProtonAPIError.unauthorized }
        let next = ProtonSession(uid: auth.uid.isEmpty ? s.uid : auth.uid,
                                 accessToken: auth.accessToken, refreshToken: auth.refreshToken)
        session = next
        return next
    }

    /// Every session replacement goes through here: bumps the epoch and
    /// drops any refresh belonging to the previous session.
    private func replaceSession(with next: ProtonSession?) {
        epoch &+= 1
        refreshTask?.cancel()
        refreshTask = nil
        session = next
    }
}
