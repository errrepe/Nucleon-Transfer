// Nucleon Transfer — session orchestrator (memory only, like the official
// Proton Drive app: no Keychain, no disk persistence; re-login each launch).
// Flow: info -> hashPassword(v4, bcrypt) -> SRP proofs -> /auth/v4
//       -> verify serverProof -> optional 2FA.
// 401 anywhere -> single /auth/v4/refresh retry (mirrors go-proton-api Client.doRes).
import CryptoKit
import Foundation

/// In-memory session. Tokens never touch disk; unlocked key seeds never
/// leave their owning actor either (see KeyringCache).
struct ProtonSession: Codable, Sendable, Equatable {
    var uid: String
    var accessToken: String
    var refreshToken: String
}

actor SessionManager {
    private var session: ProtonSession?
    private let api: APIClient
    private let bcrypt: any BcryptHasher

    init(api: APIClient = APIClient(), bcrypt: any BcryptHasher = ProtonBcryptHasher()) {
        self.api = api
        self.bcrypt = bcrypt
    }

    var isSignedIn: Bool { session != nil }
    var uid: String? { session?.uid }

    /// Current tokens for authed API calls (nil when signed out).
    func credentials() -> ProtonSession? { session }

    /// Runs `op` with (uid, accessToken), refreshing once on 401 and retrying
    /// (mirrors go-proton-api Client.doRes).
    func withAuth<T: Sendable>(_ op: @Sendable (String, String) async throws -> T) async throws -> T {
        guard let creds = session else { throw ProtonAPIError.unauthorized }
        do {
            return try await op(creds.uid, creds.accessToken)
        } catch let e as ProtonAPIError where e == .unauthorized {
            try await refresh()
            guard let retry = session else { throw ProtonAPIError.unauthorized }
            return try await op(retry.uid, retry.accessToken)
        }
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
        let hashed = try PasswordHash.hash(version: info.version, password: password,
                                           username: username, salt: salt,
                                           modulus: modulus, bcrypt: bcrypt)
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
        guard constantTimeEqual(serverProof, proofs.expectedServerProof) else {
            throw ProtonAPIError.invalidServerProof
        }
        let next = ProtonSession(uid: res.auth.uid, accessToken: res.auth.accessToken,
                                 refreshToken: res.auth.refreshToken)
        session = next
        if res.auth.requires2FA { throw ProtonAPIError.needs2FA }
    }

    func submit2FA(code: String) async throws {
        guard let s = session else { throw ProtonAPIError.unauthorized }
        try await api.auth2FA(code: code, uid: s.uid, accessToken: s.accessToken)
    }

    /// Ends the session: best-effort server-side logout (DELETE /auth/v4,
    /// go-proton-api auth.go `Client.AuthDelete`) while the token is still
    /// held, then local clear. API failures are ignored — local sign-out
    /// always wins.
    func signOut() async {
        if let s = session {
            try? await api.authDelete(uid: s.uid, accessToken: s.accessToken)
        }
        session = nil
    }

    /// Refresh tokens proactively (long syncs expire quickly — rclone #7381).
    func refresh() async throws {
        guard let s = session else { throw ProtonAPIError.unauthorized }
        let state = try SecureRandom.bytes(32)
        let body = AuthRefreshRequest(uid: s.uid, refreshToken: s.refreshToken,
                                      state: state.base64EncodedString(), accessToken: s.accessToken)
        let auth = try await api.authRefresh(body)
        session = ProtonSession(uid: auth.uid.isEmpty ? s.uid : auth.uid,
                                accessToken: auth.accessToken, refreshToken: auth.refreshToken)
    }
}

private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}
