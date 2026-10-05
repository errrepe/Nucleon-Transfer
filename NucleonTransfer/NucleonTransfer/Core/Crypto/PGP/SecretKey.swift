// Nucleon Transfer — secret-key packet parse + unlock (RFC 4880 §5.5.3).
// Supports v4 keys, S2K usages 0/254/255, AES symmetric algos. EC secret MPIs
// are left-padded to 32 bytes (Ed25519/X25519 seeds with leading zero bits).
import CryptoKit
import Foundation

enum SecretKeyError: Error, Sendable {
    case unsupportedVersion(UInt8)
    case unsupportedAlgo(UInt8)
    case truncated
    case sha1Mismatch
    case checksumMismatch
}

/// Multi-precision integer reader (2-octet bit length + big-endian bytes).
enum MPI {
    /// Returns (raw bytes, next offset).
    static func read(_ data: Data, from offset: Int) throws -> (Data, Int) {
        guard offset + 2 <= data.count else { throw SecretKeyError.truncated }
        let bitlen = (Int(data[data.startIndex + offset]) << 8) | Int(data[data.startIndex + offset + 1])
        let byteLen = (bitlen + 7) / 8
        let start = offset + 2
        guard start + byteLen <= data.count else { throw SecretKeyError.truncated }
        return (data[start..<(start + byteLen)], start + byteLen)
    }
}

struct SecretKeyPacket: Sendable {
    var version: UInt8
    var publicAlgo: UInt8
    /// Curve OID for EC keys (algo 18/19/22), e.g. Ed25519 / Cv25519.
    var curveOID: Data?
    /// Raw public point MPI bytes (for public-match verification after unlock).
    var publicPoint: Data?
    /// Public packet body (version..end of public material) for v4 fingerprinting.
    var publicBody: Data
    /// KDF params for ECDH (algo 18): hash + cipher IDs from the packet.
    var kdfHash: UInt8?
    var kdfCipher: UInt8?
    var s2kUsage: UInt8
    var symmetricAlgo: UInt8?
    var s2kSpec: Data?
    var iv: Data?
    /// Ciphertext: encrypted MPI(s) + checksum (usage 254/255), or raw (usage 0).
    var secretData: Data

    static func parse(body: Data) throws -> SecretKeyPacket {
        var o = body.startIndex
        func take(_ n: Int) throws -> Data {
            guard let e = body.index(o, offsetBy: n, limitedBy: body.endIndex), e <= body.endIndex else {
                throw SecretKeyError.truncated
            }
            defer { o = e }
            return body[o..<e]
        }
        guard body.count >= 6 else { throw SecretKeyError.truncated }
        let version = body[o]; o = body.index(after: o)
        guard version == 4 else { throw SecretKeyError.unsupportedVersion(version) }
        o = body.index(o, offsetBy: 4) // creation time
        let algo = body[o]; o = body.index(after: o)

        var curveOID: Data? = nil
        var publicPoint: Data? = nil
        var kdfHash: UInt8? = nil
        var kdfCipher: UInt8? = nil
        switch algo {
        case 1: // RSA: n, e
            for _ in 0..<2 { let (_, n) = try MPI.read(body, from: o - body.startIndex); o = body.startIndex + n }
        case 16: // ElGamal: p, g, y
            for _ in 0..<3 { let (_, n) = try MPI.read(body, from: o - body.startIndex); o = body.startIndex + n }
        case 17: // DSA: p, q, g, y
            for _ in 0..<4 { let (_, n) = try MPI.read(body, from: o - body.startIndex); o = body.startIndex + n }
        case 18, 19, 22: // ECDH/ECDSA/EdDSA: curve OID + point MPI
            let oidLen = Int(body[o]); o = body.index(after: o)
            curveOID = try take(oidLen)
            let (point, n) = try MPI.read(body, from: o - body.startIndex)
            publicPoint = Data(point)
            o = body.startIndex + n
            if algo == 18 {
                // ECDH KDF params: 1-octet length + (0x01, hashID, symID).
                let kdfLen = Int(body[o]); o = body.index(after: o)
                let kdf = try take(kdfLen)
                if kdf.count >= 3 {
                    kdfHash = kdf[kdf.startIndex + 1]
                    kdfCipher = kdf[kdf.startIndex + 2]
                }
            }
        default:
            throw SecretKeyError.unsupportedAlgo(algo)
        }

        let publicEnd = o // secret fields (s2kUsage..) begin here
        let s2kUsage = body[o]; o = body.index(after: o)
        var symmetricAlgo: UInt8? = nil
        var s2kSpec: Data? = nil
        var iv: Data? = nil
        if s2kUsage == 254 || s2kUsage == 255 {
            symmetricAlgo = body[o]; o = body.index(after: o)
            let specStart = o
            let s2kType = body[o]
            let specLen: Int
            switch s2kType {
            case 0: specLen = 2
            case 1: specLen = 10
            case 3: specLen = 11
            default: throw PGPHashError.malformedS2K
            }
            guard let specEnd = body.index(o, offsetBy: specLen, limitedBy: body.endIndex) else {
                throw SecretKeyError.truncated
            }
            s2kSpec = body[o..<specEnd]
            o = specEnd
            _ = specStart
            let blockSize = 16 // AES only (enforced at unlock)
            iv = try take(blockSize)
        } else if s2kUsage != 0 {
            throw SecretKeyError.unsupportedAlgo(s2kUsage)
        }
        return SecretKeyPacket(
            version: version, publicAlgo: algo, curveOID: curveOID, publicPoint: publicPoint,
            publicBody: Data(body[body.startIndex..<publicEnd]),
            kdfHash: kdfHash, kdfCipher: kdfCipher,
            s2kUsage: s2kUsage, symmetricAlgo: symmetricAlgo, s2kSpec: s2kSpec, iv: iv,
            secretData: Data(body[o...])
        )
    }
}

enum SecretKeyUnlock {
    /// Decrypts (verifying SHA-1/simple checksum) and returns the plaintext:
    /// secret MPI(s) + checksum. Proton key packets carry NO random prefix
    /// here — plain CFB from the stored IV (verified empirically: secretData
    /// is exactly MPI + SHA-1 on current v4 keys).
    static func decrypt(_ packet: SecretKeyPacket, passphrase: Data) throws -> Data {
        guard packet.s2kUsage == 254 || packet.s2kUsage == 255 else {
            throw SecretKeyError.unsupportedAlgo(packet.s2kUsage)
        }
        guard let sym = packet.symmetricAlgo,
              let spec = packet.s2kSpec,
              let iv = packet.iv else { throw SecretKeyError.truncated }
        let keyLen = try PGPSymmetricAlgo.keyLength(id: sym)
        var (key, _) = try S2K.derive(spec: spec, passphrase: passphrase, keyLength: keyLen)
        defer { SecureBytes.wipe(&key) }
        return try decryptWithIV(secretData: packet.secretData, iv: iv, key: key, usage: packet.s2kUsage)
    }

    /// Correct decrypt for Proton secret keys: plain CFB from the stored IV,
    /// then checksum verification over everything except the checksum itself.
    static func decryptWithIV(secretData: Data, iv: Data, key: Data, usage: UInt8) throws -> Data {
        let plain = try AESBlock.cfbDecrypt(ciphertext: secretData, key: key, iv: iv)
        if usage == 254 {
            guard plain.count >= 20 else { throw SecretKeyError.truncated }
            let body = plain.prefix(plain.count - 20)
            let expect = plain.suffix(20)
            let got = try PGPHash.digest(id: 2, body)
            guard got == expect else { throw SecretKeyError.sha1Mismatch }
        } else {
            guard plain.count >= 2 else { throw SecretKeyError.truncated }
            let body = plain.prefix(plain.count - 2)
            var sum: UInt32 = 0
            for b in body { sum = (sum + UInt32(b)) & 0xFFFF }
            let expect = (UInt16(plain[plain.count - 2]) << 8) | UInt16(plain[plain.count - 1])
            guard UInt16(sum & 0xFFFF) == expect else { throw SecretKeyError.checksumMismatch }
        }
        return plain
    }

    /// First secret MPI of the decrypted block, left-padded to 32 bytes
    /// (Ed25519 seeds are raw octets). No prefix to skip on current packets.
    static func secretScalar(plaintext: Data, prefixLen: Int = 0) throws -> Data {
        let start = plaintext.startIndex + prefixLen
        let (mpi, _) = try MPI.read(plaintext, from: start - plaintext.startIndex)
        var scalar = Data(repeating: 0, count: max(0, 32 - mpi.count))
        scalar.append(contentsOf: mpi.suffix(32))
        return scalar
    }

    /// X25519 secret scalar: stored as a big-endian MPI number, so the bytes
    /// must be reversed to little-endian for CryptoKit (verified live).
    /// Ed25519 seeds (opaque octets) use secretScalar directly.
    static func ecdhScalar(plaintext: Data, prefixLen: Int = 0) throws -> Data {
        Data(try secretScalar(plaintext: plaintext, prefixLen: prefixLen).reversed())
    }
}

/// Public-match check: proves the decrypted seed is the right key without
/// exposing it (compare-only, constant size).
enum SecretKeyVerify {
    /// EC point MPIs are 0x40-prefixed 32-octet values (RFC 9580); the seed
    /// MPI is the raw scalar. Both are left-padded to 32 for comparison.
    private static func normPoint(_ mpi: Data) -> Data {
        var p = mpi
        if p.count == 33, p.first == 0x40 { p = p.dropFirst() }
        var out = Data(repeating: 0, count: max(0, 32 - p.count))
        out.append(contentsOf: p.suffix(32))
        return out
    }

    static func ed25519PublicMatches(seed: Data, pointMPI: Data) -> Bool {
        let point = normPoint(pointMPI)
        guard seed.count == 32, point.count == 32,
              let priv = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            return false
        }
        return priv.publicKey.rawRepresentation == point
    }

    static func x25519PublicMatches(scalar: Data, pointMPI: Data) -> Bool {
        let point = normPoint(pointMPI)
        guard scalar.count == 32, point.count == 32,
              let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar) else {
            return false
        }
        return priv.publicKey.rawRepresentation == point
    }
}
