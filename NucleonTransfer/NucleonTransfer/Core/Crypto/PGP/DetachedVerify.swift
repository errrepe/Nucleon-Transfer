// Nucleon Transfer — detached signature parse + Ed25519 verify (F3b-3).
// v4 binary-doc signatures (type 0x00): digest = Hash(data || trailer),
// trailer = body[0..<hashedEnd] + [version, 0xFF] + len32BE(hashedEnd).
// Matches go-crypto signature.go signPrepareHash/buildHashSuffix.
// Only SHA-2 signature hashes are accepted (F8.1-S3): MD5/SHA-1 are
// collision-broken, so verify throws `SigError.weakHash` for them.
import CryptoKit
import Foundation

enum SigError: Error, Sendable {
    case badPacket
    case unsupportedAlgo(UInt8)
    case hashMismatch // hash-left quick reject (or wrong hash algo)
    case invalidSignature
    /// Signature hash algorithm is not in `DetachedSig.allowedHashAlgos`
    /// (MD5 = 1, SHA-1 = 2, RIPEMD-160 = 3, or unknown).
    case weakHash(UInt8)
}

struct DetachedSig: Sendable {
    var version: UInt8
    var type: UInt8
    var publicAlgo: UInt8
    var hashAlgo: UInt8
    /// Trailer suffix for digest computation (hashed area + version/FF/len).
    var trailer: Data
    /// Ed25519 64-byte signature (R || S).
    var edSignature: Data

    static func parse(body: Data) throws -> DetachedSig {
        var o = body.startIndex
        func u8() throws -> UInt8 {
            guard o < body.endIndex else { throw SigError.badPacket }
            defer { o = body.index(after: o) }
            return body[o]
        }
        func take(_ n: Int) throws -> Data {
            guard let e = body.index(o, offsetBy: n, limitedBy: body.endIndex) else {
                throw SigError.badPacket
            }
            defer { o = e }
            return body[o..<e]
        }
        let version = try u8()
        guard version == 4 else { throw SigError.badPacket }
        let type = try u8()
        let algo = try u8()
        guard algo == 22 else { throw SigError.unsupportedAlgo(algo) }
        let hashAlgo = try u8()
        let hlenHi = Int(try u8()), hlenLo = Int(try u8())
        let hashedLen = (hlenHi << 8) | hlenLo
        _ = try take(hashedLen)
        let ulenHi = Int(try u8()), ulenLo = Int(try u8())
        _ = try take((ulenHi << 8) | ulenLo)
        let hashLeft = try take(2)
        // Ed25519 signature encodings in the wild: GnuPG emits R and S as two
        // MPIs; some stacks (go-crypto) store raw R||S (64 octets); older code
        // used a single 64-byte MPI. Accept each iff it consumes the packet
        // tail EXACTLY (no trailing garbage); left-pad short components.
        let tailStart = o - body.startIndex
        let tail = Data(body[o...])
        var edSignature: Data? = nil
        // 1) single MPI covering the whole tail (<= 64 bytes content).
        if let (one, next) = try? MPI.read(body, from: tailStart), next - tailStart == tail.count, one.count <= 64 {
            var s = Data(repeating: 0, count: 64 - one.count)
            s.append(contentsOf: one)
            edSignature = s
        }
        // 2) two MPIs (R, S), exact consumption.
        if edSignature == nil,
           let (r, n1) = try? MPI.read(body, from: tailStart),
           let (s2, n2) = try? MPI.read(body, from: n1),
           n2 - tailStart == tail.count {
            var sig = Data(repeating: 0, count: max(0, 32 - r.count))
            sig.append(contentsOf: r.suffix(32))
            let pad = Data(repeating: 0, count: max(0, 32 - s2.count))
            sig.append(contentsOf: pad)
            sig.append(contentsOf: s2.suffix(32))
            edSignature = sig
        }
        // 3) raw 64 octets (go-crypto emission).
        if edSignature == nil, tail.count == 64 {
            edSignature = tail
        }
        guard let edSig = edSignature, edSig.count == 64 else {
            throw SigError.badPacket
        }

        let hashedEnd = (4 + 2 + hashedLen) // ver,type,algo,hash + len16 + subpackets
        var trailer = Data(body[body.startIndex..<(body.startIndex + hashedEnd)])
        trailer.append(version)
        trailer.append(0xFF)
        let l = UInt32(hashedEnd)
        trailer.append(UInt8((l >> 24) & 0xFF))
        trailer.append(UInt8((l >> 16) & 0xFF))
        trailer.append(UInt8((l >> 8) & 0xFF))
        trailer.append(UInt8(l & 0xFF))
        _ = hashLeft
        return DetachedSig(version: version, type: type, publicAlgo: algo,
                           hashAlgo: hashAlgo, trailer: trailer, edSignature: edSig,
                           hashLeftExpected: Data(hashLeft))
    }

    private var hashLeftExpected: Data

    init(version: UInt8, type: UInt8, publicAlgo: UInt8, hashAlgo: UInt8,
         trailer: Data, edSignature: Data, hashLeftExpected: Data) {
        self.version = version
        self.type = type
        self.publicAlgo = publicAlgo
        self.hashAlgo = hashAlgo
        self.trailer = trailer
        self.edSignature = edSignature
        self.hashLeftExpected = hashLeftExpected
    }

    /// Signature hash IDs accepted by `verify`: SHA-256, SHA-384, SHA-512,
    /// SHA-224. MD5 (1) and SHA-1 (2) stay in `PGPHash` only for the MDC
    /// and S2K, never for signatures.
    static let allowedHashAlgos: Set<UInt8> = [8, 9, 10, 11]

    /// Verifies over `data` with the signer's 32-byte Ed25519 public key
    /// (0x40 prefix tolerated). Throws `SigError.weakHash` for MD5/SHA-1
    /// (or any non-SHA-2) signature hashes.
    func verify(data: Data, signerPointMPI: Data) throws -> Bool {
        guard Self.allowedHashAlgos.contains(hashAlgo) else { throw SigError.weakHash(hashAlgo) }
        var point = signerPointMPI
        if point.count == 33, point.first == 0x40 { point = point.dropFirst() }
        guard point.count == 32, edSignature.count == 64,
              let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: point) else {
            return false
        }
        var input = data
        input.append(trailer)
        let digest = try PGPHash.digest(id: hashAlgo, input)
        guard digest.prefix(2) == hashLeftExpected else { return false }
        return pub.isValidSignature(edSignature, for: digest)
    }
}
