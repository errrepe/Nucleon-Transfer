// Nucleon Transfer — Proton API error mapping.
// Reference: go-proton-api client.go (401 -> refresh), manager_auth.go, proton-cli HV handling.
import Foundation

enum ProtonAPIError: Error, Sendable, Equatable {
    case api(code: Int, message: String)
    case unauthorized
    case needs2FA
    case humanVerificationRequired
    case invalidServerProof
    case invalidModulusSignature
    case srpParamsOutOfBounds(String)
    /// Legacy password-hash scheme (auth version < 3, go-srp hash.go) — refused.
    case unsupportedAuthVersion(Int)
    /// SecRandomCopyBytes reported failure; no fallback randomness is used.
    case secureRandomFailed
    case bcryptNotAvailable
    case invalidBcryptSalt
    case keyVerificationFailed
    /// 2028 Too many recent logins (or generic rate limit): NEVER auto-retry
    /// logins — surface immediately and back off. One spaced login per batch.
    case rateLimited
    /// Non-2xx HTTP response that carried no usable Proton envelope success
    /// (storage host, or an API body that would not decode). `status` is the
    /// HTTP status (for retry classification: 429/5xx transient, etc.);
    /// `code` is the envelope `Code` when the body had one. `retryAfter` is
    /// the parsed `Retry-After` header in seconds (F8.2-R3; 429/503 answers
    /// carry it — go-proton-api retries 429/503 honouring it via resty).
    case http(status: Int, code: Int?, message: String, retryAfter: TimeInterval? = nil)
    /// A server-supplied storage URL failed the https + Proton-host check
    /// (`AppVersion.storageHostSuffixes`); nothing was sent. Carries only the
    /// host (block URLs embed tokens in-path — never echo the full URL).
    case untrustedStorageHost(String)
    case transport(Error)

    static func == (lhs: ProtonAPIError, rhs: ProtonAPIError) -> Bool {
        switch (lhs, rhs) {
        case (.unauthorized, .unauthorized),
             (.needs2FA, .needs2FA),
             (.humanVerificationRequired, .humanVerificationRequired),
             (.invalidServerProof, .invalidServerProof),
             (.invalidModulusSignature, .invalidModulusSignature),
             (.bcryptNotAvailable, .bcryptNotAvailable),
             (.invalidBcryptSalt, .invalidBcryptSalt),
             (.keyVerificationFailed, .keyVerificationFailed),
             (.secureRandomFailed, .secureRandomFailed),
             (.rateLimited, .rateLimited):
            return true
        case let (.api(c1, m1), .api(c2, m2)):
            return c1 == c2 && m1 == m2
        case let (.srpParamsOutOfBounds(a), .srpParamsOutOfBounds(b)):
            return a == b
        case let (.http(s1, c1, m1, r1), .http(s2, c2, m2, r2)):
            return s1 == s2 && c1 == c2 && m1 == m2 && r1 == r2
        case let (.untrustedStorageHost(a), .untrustedStorageHost(b)):
            return a == b
        case let (.unsupportedAuthVersion(a), .unsupportedAuthVersion(b)):
            return a == b
        default:
            return false
        }
    }
}

/// Minimal envelope shared by Proton REST responses: { Code, Error }.
struct ProtonEnvelope: Decodable, Sendable {
    var code: Int
    var error: String?

    enum CodingKeys: String, CodingKey {
        case code = "Code"
        case error = "Error"
    }
}

extension ProtonAPIError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .unauthorized: return "Not signed in (or session expired)."
        case .needs2FA: return "Two-factor code required."
        case .humanVerificationRequired: return "Proton requires human verification. Try again later."
        case .rateLimited: return "Too many recent logins (Proton 2028 rate-limit). Wait ~10 minutes before retrying — do not log in repeatedly. If you are signed in, keep using this session."
        case .invalidServerProof: return "Server proof mismatch — possible downgrade attack. Aborted."
        case .invalidModulusSignature: return "SRP modulus signature missing or invalid."
        case let .unsupportedAuthVersion(v): return "Unsupported legacy auth version \(v)."
        case .secureRandomFailed: return "System random number generator failed."
        case .bcryptNotAvailable: return "Crypto backend missing (bcrypt)."
        case .invalidBcryptSalt: return "Malformed bcrypt salt."
        case .keyVerificationFailed: return "Unlocked key does not match its public key."
        case let .srpParamsOutOfBounds(msg): return "SRP parameter error: \(msg)."
        case let .api(code, message): return "Proton API \(code): \(message)."
        case let .http(status, code, message, _):
            if let code { return "HTTP \(status) (Proton \(code)): \(message)." }
            return "HTTP \(status): \(message)."
        case let .untrustedStorageHost(host):
            return "Refused storage URL on untrusted host \(host)."
        case let .transport(e): return e.localizedDescription
        }
    }
}
