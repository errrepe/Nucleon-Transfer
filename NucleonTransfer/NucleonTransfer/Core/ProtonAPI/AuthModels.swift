// Nucleon Transfer — Auth models mirroring go-proton-api manager_auth_types.go
// Endpoints: POST /auth/v4/info, POST /auth/v4, POST /auth/v4/2fa, POST /auth/v4/refresh
import Foundation

struct AuthInfoRequest: Encodable, Sendable {
    var username: String
    enum CodingKeys: String, CodingKey { case username = "Username" }
}

struct AuthInfo: Decodable, Sendable {
    /// Major SRP version (0...4). Current accounts use 4.
    var version: Int
    /// Modulus: base64 of clearsigned message (signature must be verified — TODO PGP).
    var modulus: String
    var salt: String
    var serverEphemeral: String
    var srpSession: String

    enum CodingKeys: String, CodingKey {
        case version = "Version"
        case modulus = "Modulus"
        case salt = "Salt"
        case serverEphemeral = "ServerEphemeral"
        case srpSession = "SRPSession"
    }
}

struct AuthRequest: Encodable, Sendable {
    var username: String
    var clientEphemeral: String // base64
    var clientProof: String     // base64
    var srpSession: String
    enum CodingKeys: String, CodingKey {
        case username = "Username"
        case clientEphemeral = "ClientEphemeral"
        case clientProof = "ClientProof"
        case srpSession = "SRPSession"
    }
}

struct ProtonAuth: Decodable, Sendable {
    var uid: String
    var accessToken: String
    var refreshToken: String
    /// SRP server proof — only `POST /auth/v4` (login) carries it. The
    /// `/auth/v4/refresh` answer has none, so it must stay optional or
    /// every refresh fails to decode (F8.5 live check: restore rejected
    /// with Code 1000). Login still requires it (SessionManager).
    var serverProof: String?
    /// Session scope: "full" vs "2fa". 2FA is required when scope contains
    /// "2fa" or TwoFA.Enabled != 0 (go-proton-api manager_auth_types.go).
    var scope: String?
    var twoFA: TwoFAInfo?

    enum CodingKeys: String, CodingKey {
        case uid = "UID"
        case accessToken = "AccessToken"
        case refreshToken = "RefreshToken"
        case serverProof = "ServerProof"
        case scope = "Scope"
        case twoFA = "2FA"
    }

    /// True when the server gates this session behind a second factor.
    var requires2FA: Bool {
        if let scope, scope.lowercased().contains("2fa") { return true }
        return (twoFA?.enabled ?? 0) != 0
    }
}

struct TwoFAInfo: Decodable, Sendable {
    /// 0 = none, 1 = TOTP, 2 = FIDO2, 3 = both (go-proton-api TwoFAStatus).
    var enabled: Int?
    enum CodingKeys: String, CodingKey { case enabled = "Enabled" }
}

struct Auth2FARequest: Encodable, Sendable {
    var twoFACode: String
    enum CodingKeys: String, CodingKey { case twoFACode = "TwoFactorCode" }
}

struct AuthRefreshRequest: Encodable, Sendable {
    var uid: String
    var refreshToken: String
    var responseType = "token"
    var grantType = "refresh_token"
    var redirectURI = "https://protonmail.ch"
    var state: String
    /// Omitted from the body when nil: a restored session (F8.5) refreshes
    /// before it has an access token. Live sessions still send it.
    var accessToken: String?

    enum CodingKeys: String, CodingKey {
        case uid = "UID"
        case refreshToken = "RefreshToken"
        case responseType = "ResponseType"
        case grantType = "GrantType"
        case redirectURI = "RedirectURI"
        case state = "State"
        case accessToken = "AccessToken"
    }
}
