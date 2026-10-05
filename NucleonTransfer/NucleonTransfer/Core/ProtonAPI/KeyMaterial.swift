// Nucleon Transfer — key-material models + salted key password.
// Flow (mirrors rclone/Proton-API-Bridge common/keyring.go + user.go):
//   GET /core/v4/keys/salts (password scope only, shortly after login)
//   -> find salt for primary user key ID
//   -> saltedKeyPass = last 31 chars of bcrypt(keyPass, dotSlash(keySalt))
//   -> unlock user secret keys with saltedKeyPass (NOT the raw password)
import Foundation

// MARK: - Key salts

struct KeySaltEntry: Decodable, Sendable {
    var id: String
    /// base64 salt; null for keys that need none (filter before use).
    var keySalt: String?
    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case keySalt = "KeySalt"
    }
}

struct KeySaltsResponse: Decodable, Sendable {
    var keySalts: [KeySaltEntry]
    enum CodingKeys: String, CodingKey { case keySalts = "KeySalts" }
}

// MARK: - User / address keys

/// A Proton key reference. For user keys Token/Signature are typically empty
/// (direct saltedKeyPass unlock); address keys carry Token+Signature (see F3b-2).
struct ProtonKeyRef: Decodable, Sendable {
    var id: String
    var privateKey: String // armored secret key
    /// Go Bool marshals as 0/1 int, not JSON boolean.
    var primary: Int?
    var active: Int?
    var token: String?
    var signature: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case privateKey = "PrivateKey"
        case primary = "Primary"
        case active = "Active"
        case token = "Token"
        case signature = "Signature"
    }

    var isPrimary: Bool { primary == 1 }
    var isActive: Bool { active ?? 1 == 1 }
}

struct ProtonUser: Decodable, Sendable {
    /// Account fields mirror go-proton-api user_types.go (`type User`):
    /// Name/DisplayName/Email/UsedSpace/MaxSpace. All optional — the
    /// synthesized Decodable uses decodeIfPresent, so minimal /users
    /// payloads (Keys only) still decode.
    /// `ID` — the stable Proton user ID (go-proton-api `User.ID`); scopes
    /// the persisted upload queue to its account (F8.2-R7 / B12).
    var id: String?
    var name: String?
    var displayName: String?
    var email: String?
    var usedSpace: Int64?
    var maxSpace: Int64?
    var keys: [ProtonKeyRef]

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case name = "Name"
        case displayName = "DisplayName"
        case email = "Email"
        case usedSpace = "UsedSpace"
        case maxSpace = "MaxSpace"
        case keys = "Keys"
    }

    var primaryKey: ProtonKeyRef? {
        keys.first(where: \.isPrimary) ?? keys.first
    }
}

struct ProtonUserResponse: Decodable, Sendable {
    var user: ProtonUser
    enum CodingKeys: String, CodingKey { case user = "User" }
}

struct ProtonAddress: Decodable, Sendable {
    var id: String
    var email: String?
    var keys: [ProtonKeyRef]

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case email = "Email"
        case keys = "Keys"
    }
}

struct AddressesResponse: Decodable, Sendable {
    var addresses: [ProtonAddress]
    enum CodingKeys: String, CodingKey { case addresses = "Addresses" }
}

// MARK: - Salted key password

enum MailboxPassword {
    /// go-srp MailboxPassword + rclone SaltForKey: bcrypt(keyPass, dotSlash(keySalt)),
    /// keeping the last 31 chars (the digest; drops "$2y$10$"+22 salt prefix).
    static func salted(
        keyPass: Data,
        keySalt: Data,
        hasher: any BcryptHasher = ProtonBcryptHasher()
    ) throws -> Data {
        let encoded = DotSlashBase64.encode(keySalt)
        var full = try hasher.hash(password: keyPass, dotSlashSalt: "$2y$10$\(encoded)")
        defer { SecureBytes.wipe(&full) }
        guard full.count >= 31 else { throw ProtonAPIError.invalidBcryptSalt }
        // Fresh storage for the result, so wiping `full` hits its own bytes.
        return Data([UInt8](full.suffix(31)))
    }
}
