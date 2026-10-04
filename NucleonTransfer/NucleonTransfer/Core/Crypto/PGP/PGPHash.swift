// Nucleon Transfer — OpenPGP hashes + string-to-key (RFC 4880 §3.6/3.7).
// Hash IDs: 1 MD5, 2 SHA-1, 8 SHA-256, 9 SHA-384, 10 SHA-512, 11 SHA-224.
// MD5/SHA-1 remain here for the SEIPDv1 MDC and legacy S2K only; signature
// verification restricts itself to SHA-2 (DetachedSig.allowedHashAlgos).
import CommonCrypto
import CryptoKit
import Foundation

enum PGPHashError: Error, Sendable {
    case unsupportedHash(UInt8)
    case malformedS2K
}

enum PGPHash {
    static func digestLength(id: UInt8) throws -> Int {
        switch id {
        case 1: return Int(CC_MD5_DIGEST_LENGTH)
        case 2: return Int(CC_SHA1_DIGEST_LENGTH)
        case 8: return Int(CC_SHA256_DIGEST_LENGTH)
        case 9: return Int(CC_SHA384_DIGEST_LENGTH)
        case 10: return Int(CC_SHA512_DIGEST_LENGTH)
        case 11: return Int(CC_SHA224_DIGEST_LENGTH)
        default: throw PGPHashError.unsupportedHash(id)
        }
    }

    static func digest(id: UInt8, _ data: Data) throws -> Data {
        switch id {
        case 1:
            return Data(Insecure.MD5.hash(data: data))
        case 2:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            _ = data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(data.count), &out) }
            return Data(out)
        case 8:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            _ = data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &out) }
            return Data(out)
        case 9:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            _ = data.withUnsafeBytes { CC_SHA384($0.baseAddress, CC_LONG(data.count), &out) }
            return Data(out)
        case 10:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            _ = data.withUnsafeBytes { CC_SHA512($0.baseAddress, CC_LONG(data.count), &out) }
            return Data(out)
        case 11:
            var out = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            _ = data.withUnsafeBytes { CC_SHA224($0.baseAddress, CC_LONG(data.count), &out) }
            return Data(out)
        default:
            throw PGPHashError.unsupportedHash(id)
        }
    }
}

/// String-to-key. Consumes the specifier at `spec` start, returns
/// (derivedKey, bytesConsumed).
enum S2K {
    /// OpenPGP coded iteration count: (16 + (c & 15)) << ((c >> 4) + 6).
    static func codedCount(_ c: UInt8) -> Int {
        (16 + (Int(c) & 15)) << ((Int(c) >> 4) + 6)
    }

    static func derive(spec: Data, passphrase: Data, keyLength: Int) throws -> (key: Data, consumed: Int) {
        guard !spec.isEmpty else { throw PGPHashError.malformedS2K }
        let type = spec[spec.startIndex]
        switch type {
        case 0: // Simple: hash(passphrase)
            guard spec.count >= 2 else { throw PGPHashError.malformedS2K }
            let hashID = spec[spec.index(spec.startIndex, offsetBy: 1)]
            return (try expand(hashID: hashID, data: passphrase, keyLength: keyLength), 2)
        case 1, 3: // Salted / Iterated: hash([salt +] passphrase)
            guard spec.count >= 10 else { throw PGPHashError.malformedS2K }
            let hashID = spec[spec.index(spec.startIndex, offsetBy: 1)]
            let salt = spec[spec.index(spec.startIndex, offsetBy: 2)..<spec.index(spec.startIndex, offsetBy: 10)]
            if type == 1 {
                return (try expand(hashID: hashID, data: Data(salt) + passphrase, keyLength: keyLength), 10)
            }
            guard spec.count >= 11 else { throw PGPHashError.malformedS2K }
            let count = codedCount(spec[spec.index(spec.startIndex, offsetBy: 10)])
            let data = Data(salt) + passphrase
            return (try expandIterated(hashID: hashID, data: data, count: count, keyLength: keyLength), 11)
        default:
            // 2 = reserved, 4+ = private/experimental, 5 = Argon2 (RFC 9580, out of scope).
            throw PGPHashError.malformedS2K
        }
    }

    /// RFC 4880 §3.7.1.3 key expansion: H(prefixes + data), zero-prefixed rounds.
    private static func expand(hashID: UInt8, data: Data, keyLength: Int) throws -> Data {
        var key = Data()
        var prefix = 0
        while key.count < keyLength {
            var input = Data(repeating: 0, count: prefix)
            input.append(data)
            key.append(try PGPHash.digest(id: hashID, input))
            prefix += 1
        }
        return key.prefix(keyLength)
    }

    private static func expandIterated(hashID: UInt8, data: Data, count: Int, keyLength: Int) throws -> Data {
        // Cycle `data` to exactly `count` octets per round.
        var cycled = Data()
        cycled.reserveCapacity(count)
        while cycled.count < count {
            let need = count - cycled.count
            cycled.append(data.prefix(need))
        }
        var key = Data()
        var prefix = 0
        while key.count < keyLength {
            var input = Data(repeating: 0, count: prefix)
            input.append(cycled)
            key.append(try PGPHash.digest(id: hashID, input))
            prefix += 1
        }
        return key.prefix(keyLength)
    }
}
