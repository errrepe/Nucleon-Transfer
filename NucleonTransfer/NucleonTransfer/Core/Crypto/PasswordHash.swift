// Nucleon Transfer — password hashing dispatch per go-srp/hash.go
// Bcrypt core is vendored (Core/Crypto/BCrypt, MIT vapor-community/bcrypt).
import Foundation

protocol BcryptHasher: Sendable {
    /// bcrypt with cost 10 and given dot-slash encoded salt string, matching
    /// go-srp bcryptHash(password, "$2y$10$"+encodedSalt). Returns raw hash bytes.
    func hash(password: Data, dotSlashSalt: String) throws -> Data
}

struct UnimplementedBcryptHasher: BcryptHasher {
    func hash(password: Data, dotSlashSalt: String) throws -> Data {
        throw ProtonAPIError.bcryptNotAvailable
    }
}

enum PasswordHash {
    static func hash(
        version: Int,
        password: Data,
        username: String,
        salt: Data,
        modulus: Data,
        bcrypt: any BcryptHasher
    ) throws -> Data {
        switch version {
        case 3, 4:
            // encodedSalt = dotSlashBase64(salt + "proton")
            var salted = salt
            salted.append(contentsOf: "proton".utf8)
            let encoded = DotSlashBase64.encode(salted)
            var crypted = try bcrypt.hash(password: password, dotSlashSalt: "$2y$10$\(encoded)")
            var input = crypted + modulus
            defer {
                SecureBytes.wipe(&crypted)
                SecureBytes.wipe(&input)
            }
            return ExpandHash.expand(input)
        default:
            // Versions 0/1/2 are legacy MD5/SHA-512-prehash schemes (go-srp
            // hash.go); refused fail-closed (F8.1-S1). Unknown future versions
            // are refused too rather than guessed.
            throw ProtonAPIError.unsupportedAuthVersion(version)
        }
    }
}
