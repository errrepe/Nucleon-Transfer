// Nucleon Transfer — SED/SEIPDv1 encrypt (RFC 4880 §13.9, F4.1, F8.3-P1).
// Exact inverse of SEDDecrypt: random prefix + check bytes, then NoResync
// CFB + MDC (SHA-1 over full prefix + data + D3 14) for tag 18 v1. NoResync
// OpenPGP CFB is standard CFB-128 with a zero IV, so one CCCryptor streams
// prefix, data and MDC straight into the preallocated output (no plaintext
// copy). Resync CFB (tag 9, `useMDC: false`) is kept only so tests can
// build the legacy packets the decrypt side must refuse.
import CommonCrypto
import CryptoKit
import Foundation

enum SEDEncryptError: Error, Sendable {
    case badKeyLength
}

enum SEDEncrypt {
    /// Encrypts inner packet bytes with the session key.
    /// - `useMDC` true: returns version octet 0x01 + NoResync CFB over
    ///   (prefix + inner + D3 14 + MDC). False: resync CFB over
    ///   (prefix + inner). Returns the SED body (caller frames tag 9/18).
    static func encrypt(inner: Data, sessionKey: Data, symAlgoID: UInt8, useMDC: Bool) throws -> Data {
        let keyLen = try PGPSymmetricAlgo.keyLength(id: symAlgoID)
        guard sessionKey.count == keyLen else { throw SEDEncryptError.badKeyLength }
        guard useMDC else { return try resyncEncrypt(prefix: randomPrefix(), inner: inner, key: sessionKey) }
        return try seipd(innerParts: [inner], key: sessionKey, frame: false)
    }

    /// Complete SEIPDv1 packet (tag 18 framing + body) over the
    /// concatenation of `innerParts`, which are streamed through the
    /// cipher and the MDC without being joined: one output allocation.
    static func seipdPacket(innerParts: [Data], sessionKey: Data, symAlgoID: UInt8) throws -> Data {
        let keyLen = try PGPSymmetricAlgo.keyLength(id: symAlgoID)
        guard sessionKey.count == keyLen else { throw SEDEncryptError.badKeyLength }
        return try seipd(innerParts: innerParts, key: sessionKey, frame: true)
    }

    private static func seipd(innerParts: [Data], key: Data, frame: Bool) throws -> Data {
        let prefix = randomPrefix()
        // MDC input (go-crypto parity) is the FULL plaintext prefix
        // (18 bytes, incl. check) + data + D3 14.
        var sha = Insecure.SHA1()
        prefix.withUnsafeBytes { sha.update(bufferPointer: $0) }
        for part in innerParts { part.withUnsafeBytes { sha.update(bufferPointer: $0) } }
        var trailer: [UInt8] = [0xD3, 0x14]
        trailer.withUnsafeBytes { sha.update(bufferPointer: $0) }
        trailer.append(contentsOf: sha.finalize())

        let innerCount = innerParts.reduce(0) { $0 + $1.count }
        let bodyCount = 1 + prefixLength + innerCount + trailer.count
        var out = frame ? PGPPacketsEncode.header(tag: 18, length: bodyCount) : Data()
        out.reserveCapacity(out.count + bodyCount)
        out.append(0x01) // SEIPD version
        var o = out.count
        out.count += bodyCount - 1
        let stream = try AESBlock.CFBStream(CCOperation(kCCEncrypt), key: key)
        try out.withUnsafeMutableBytes { dst in
            func put(_ src: UnsafeRawBufferPointer) throws {
                try stream.update(src, into: UnsafeMutableRawBufferPointer(rebasing: dst[o...]))
                o += src.count
            }
            try prefix.withUnsafeBytes(put)
            for part in innerParts { try part.withUnsafeBytes(put) }
            try trailer.withUnsafeBytes(put)
        }
        return out
    }

    private static func randomPrefix() -> [UInt8] {
        var prefix = [UInt8](repeating: 0, count: prefixLength)
        for i in 0..<16 { prefix[i] = UInt8.random(in: .min ... .max) }
        prefix[16] = prefix[14]
        prefix[17] = prefix[15]
        return prefix
    }

    /// Random prefix (one AES block) + 2 check octets.
    static let prefixLength = 18

    /// Legacy tag 9 resync CFB (RFC 4880 §13.9 steps 1-9): the 18 prefix
    /// octets are plain CFB from a zero IV; the data then restarts CFB with
    /// FR = c[2..<18]. Test-only in practice — decrypt refuses tag 9.
    private static func resyncEncrypt(prefix: [UInt8], inner: Data, key: Data) throws -> Data {
        let op = CCOperation(kCCEncrypt)
        let head = try AESBlock.cfb(op, Data(prefix), key: key, iv: nil)
        let tail = try AESBlock.cfb(op, inner, key: key, iv: head.subdata(in: 2..<prefixLength))
        return head + tail
    }
}
