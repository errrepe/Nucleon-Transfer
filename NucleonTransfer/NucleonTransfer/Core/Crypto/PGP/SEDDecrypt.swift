// Nucleon Transfer — SEIPDv1 decrypt + literal extraction (F3b-2, F8.1-S3, F8.3-P1).
// Only tag 18 v1 (MDC SHA-1) is accepted. Tag 9 (SED, no integrity
// protection) is rejected outright: decrypting it allows undetected
// ciphertext tampering (EFAIL class); go-crypto rejects it by default too.
import CommonCrypto
import CryptoKit
import Foundation

enum SEDError: Error, Sendable, Equatable {
    case badPacket
    case mdcMissing
    case mdcMismatch
    /// Tag 9 (Symmetrically Encrypted Data without MDC) — refused.
    case integrityProtectionRequired
    case unsupportedCompression(UInt8)
    case noLiteralData
}

enum SEDDecrypt {
    /// Decrypts one SEIPDv1 (tag 18) body with the session key.
    /// - `expectMDC` must be true (tag 18): body starts with version octet
    ///   0x01 (RFC 9580; GnuPG 2.5 requires it — the live Token packet
    ///   starts with 0x01), then NoResync CFB, then trailing MDC. False
    ///   (tag 9, plain SED) throws `integrityProtectionRequired`.
    /// - MDC input (go-crypto parity) is the FULL plaintext prefix (18 bytes,
    ///   incl. check) + data + D3 14 — NOT data-after-prefix alone. The
    ///   digest is compared in constant time.
    /// Returns the inner packet bytes (literal/compressed), zero-based:
    /// decrypted once into the result buffer, which is truncated in place.
    static func decrypt(sedBody: Data, sessionKey: Data, symAlgoID: UInt8, expectMDC: Bool) throws -> Data {
        guard expectMDC else { throw SEDError.integrityProtectionRequired }
        let keyLen = try PGPSymmetricAlgo.keyLength(id: symAlgoID)
        guard sessionKey.count == keyLen else { throw SEDError.badPacket }
        guard let first = sedBody.first, first == 1 else { throw SEDError.badPacket }
        let prefixLength = SEDEncrypt.prefixLength
        guard sedBody.count - 1 >= prefixLength else { throw AESError.badBlockLength }

        // NoResync OpenPGP CFB == standard CFB-128, zero IV, one cryptor.
        // The prefix goes to a small buffer (check octets verified first);
        // everything after it lands in `out`, which becomes the result.
        let stream = try AESBlock.CFBStream(CCOperation(kCCDecrypt), key: sessionKey)
        var prefix = [UInt8](repeating: 0, count: prefixLength)
        var out = Data(count: sedBody.count - 1 - prefixLength)
        try sedBody.withUnsafeBytes { raw in
            let cipher = UnsafeRawBufferPointer(rebasing: raw[1...])
            try prefix.withUnsafeMutableBytes { dst in
                try stream.update(UnsafeRawBufferPointer(rebasing: cipher[..<prefixLength]), into: dst)
            }
            // Check octets repeat the last two random prefix octets.
            guard prefix[16] == prefix[14], prefix[17] == prefix[15] else {
                throw AESError.checkBytesMismatch
            }
            try out.withUnsafeMutableBytes { dst in
                try stream.update(UnsafeRawBufferPointer(rebasing: cipher[prefixLength...]), into: dst)
            }
        }

        // MDC packet: D3 14 + SHA1 hash. The hash covers everything before
        // it — full plaintext prefix + data + the D3 14 header itself
        // (go-crypto hashes the stream including the header, then compares
        // the trailing 20 bytes). Do NOT append D3 14: it is already the
        // last 2 bytes of the hashed region. SHA-1 runs incrementally over
        // the two buffers (no concatenated copy).
        let n = out.count
        guard n >= 22, out[n - 22] == 0xD3, out[n - 21] == 0x14 else {
            throw SEDError.mdcMissing
        }
        var sha = Insecure.SHA1()
        prefix.withUnsafeBytes { sha.update(bufferPointer: $0) }
        out.withUnsafeBytes { sha.update(bufferPointer: UnsafeRawBufferPointer(rebasing: $0[..<(n - 20)])) }
        let digest = Array(sha.finalize())
        guard constantTimeEquals(digest, out[(n - 20)...]) else { throw SEDError.mdcMismatch }
        out.count = n - 22 // drop D3 14 + digest in place
        return out
    }

    /// Extracts literal data (tag 11) from inner packets.
    /// Compressed packets (tag 8) are rejected: Proton passphrase/name
    /// messages are uncompressed literals, and raw-DEFLATE needs a vendored
    /// inflater (e.g. miniz) — Apple’s Compression framework only handles
    /// zlib-wrapped streams. Verified: GnuPG-made ZIP messages fail loudly
    /// here instead of corrupting silently.
    static func literalData(_ inner: Data) throws -> Data {
        // Bodies may be slices of `inner` (no copy); parseLiteral is
        // index-relative and returns a zero-based Data.
        let packets = try PGPPackets.parseSlices(inner)
        for p in packets {
            switch p.tag {
            case 11:
                return try parseLiteral(p.body)
            case 8:
                guard !p.body.isEmpty else { throw SEDError.badPacket }
                throw SEDError.unsupportedCompression(p.body[p.body.startIndex])
            default:
                continue
            }
        }
        throw SEDError.noLiteralData
    }

    /// Literal packet: format(1) + filenameLen(1) + filename + date(4) + data.
    static func parseLiteral(_ body: Data) throws -> Data {
        var o = body.startIndex
        guard let fEnd = body.index(o, offsetBy: 2, limitedBy: body.endIndex) else {
            throw SEDError.badPacket
        }
        let fnLen = Int(body[body.index(o, offsetBy: 1)])
        o = fEnd
        guard let dStart = body.index(o, offsetBy: fnLen + 4, limitedBy: body.endIndex) else {
            throw SEDError.badPacket
        }
        return Data(body[dStart...])
    }
}
