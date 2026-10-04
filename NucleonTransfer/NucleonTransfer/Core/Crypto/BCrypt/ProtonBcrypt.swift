// Nucleon Transfer — BcryptHasher matching go-srp bcryptHash semantics:
// input "$2y$10$<22-char dot-slash salt>", cost 10, output = full 60-char
// hash string bytes ("$2y$10$<salt22><digest31>"), which SRP expands with the modulus.
// $2a$/$2x$/$2y$ share the EksBlowfish core; ASCII passwords hash identically.
import Foundation

struct ProtonBcryptHasher: BcryptHasher {
    func hash(password: Data, dotSlashSalt: String) throws -> Data {
        // Split "$2y$10$<salt22+>" — mirrors ProtonMail/bcrypt HashBytes, which
        // reads exactly the first 22 salt chars (Proton v3/v4 salts are 30 chars:
        // dotSlash(salt16 + "proton")) and echoes those 22 in the output.
        let parts = dotSlashSalt.split(separator: "$", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0].isEmpty else {
            throw ProtonAPIError.invalidBcryptSalt
        }
        let version = String(parts[1]) // "2y" (go also accepts "2a")
        guard version == "2y" || version == "2a" else {
            throw ProtonAPIError.invalidBcryptSalt
        }
        guard parts[2].count == 2, let cost = UInt(parts[2]), cost >= 4, cost <= 31 else {
            throw ProtonAPIError.invalidBcryptSalt
        }
        let saltStr = String(parts[3].prefix(22))
        guard parts[3].count >= 22,
              let saltBytes = BcryptBase64.decode(saltStr, expected: 16) else {
            throw ProtonAPIError.invalidBcryptSalt
        }

        var passwordBytes = Array(password)
        var digest = EksBlowfish.hash(password: passwordBytes, salt: saltBytes, cost: cost)
        defer {
            SecureBytes.wipe(&passwordBytes)
            SecureBytes.wipe(&digest)
        }
        // The encoded String copy cannot be wiped (best-effort, F8.1-S7);
        // the returned Data belongs to the caller.
        let full = "$\(version)$\(parts[2])$\(saltStr)" + BcryptBase64.encode(digest)
        return Data(full.utf8)
    }
}
