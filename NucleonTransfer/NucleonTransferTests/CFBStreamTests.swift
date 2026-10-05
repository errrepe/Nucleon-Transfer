// Nucleon Transfer — F8.3-P1 single-cryptor CFB cross-checks (Swift Testing).
// The production CFB runs one CCCryptor per message; this file keeps a tiny
// per-block reference (the pre-P1 algorithm: AES-ECB of the feedback
// register, RFC 4880 §13.9) and checks both directions agree on random
// data, plus the NIST SP 800-38A CFB128 vector. Offline, throwaway keys.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

private func hex(_ s: String) -> Data {
    var d = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        if let b = UInt8(s[i..<j], radix: 16) { d.append(b) }
        i = j
    }
    return d
}

private func randomBytes(_ n: Int) -> Data {
    Data((0..<n).map { _ in UInt8.random(in: .min ... .max) })
}

/// Pre-P1 reference: byte-wise OpenPGP CFB, one AES-ECB call per block.
private enum ReferenceCFB {
    /// Standard CFB-128 encrypt (decrypt = same keystream, FR fed with
    /// ciphertext either way).
    static func crypt(_ input: Data, key: Data, iv: Data, decrypt: Bool) throws -> Data {
        let p = Array(input)
        var fr = Array(iv)
        var out: [UInt8] = []
        var pos = 0
        while pos < p.count {
            let fre = try Array(AESBlock.encrypt(block: Data(fr), key: key))
            let end = min(pos + 16, p.count)
            for i in pos..<end { out.append(p[i] ^ fre[i - pos]) }
            if end - pos == 16 { fr = decrypt ? Array(p[pos..<end]) : Array(out[pos..<end]) }
            pos = end
        }
        return Data(out)
    }

    /// OpenPGP CFB decrypt with prefix, NoResync (SEIPDv1) or resync (SED).
    static func openPGPDecrypt(_ c: [UInt8], key: Data, resync: Bool) throws -> [UInt8] {
        var out: [UInt8] = []
        var fre = try Array(AESBlock.encrypt(block: Data(count: 16), key: key))
        for i in 0..<16 { out.append(c[i] ^ fre[i]) }
        fre = try Array(AESBlock.encrypt(block: Data(c[0..<16]), key: key))
        out.append(c[16] ^ fre[0])
        out.append(c[17] ^ fre[1])
        if resync {
            let rest = try crypt(Data(c[18...]), key: key, iv: Data(c[2..<18]), decrypt: true)
            return out + Array(rest)
        }
        fre[0] = c[16]
        fre[1] = c[17]
        var used = 2
        for pos in 18..<c.count {
            if used == 16 {
                fre = try Array(AESBlock.encrypt(block: Data(fre), key: key))
                used = 0
            }
            out.append(c[pos] ^ fre[used])
            fre[used] = c[pos]
            used += 1
        }
        return out
    }

    /// Reference SEIPDv1 body: 0x01 + NoResync CFB(prefix + inner + MDC).
    static func seipdEncrypt(inner: Data, key: Data) throws -> Data {
        var prefix = randomBytes(16)
        prefix.append(prefix[14])
        prefix.append(prefix[15])
        var plain = prefix + inner + Data([0xD3, 0x14])
        plain.append(Data(Insecure.SHA1.hash(data: plain)))
        // NoResync OpenPGP CFB is plain CFB with a zero IV; the per-block
        // decrypt above is checked against it separately.
        return Data([0x01]) + (try crypt(plain, key: key, iv: Data(count: 16), decrypt: false))
    }
}

struct CFBStreamTests {
    @Test func nistSP80038ACFB128Vector() throws {
        // NIST SP 800-38A F.3.13 / F.3.14 (CFB128-AES128).
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = hex("000102030405060708090a0b0c0d0e0f")
        let plain = hex("6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51"
                        + "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710")
        let cipher = hex("3b3fd92eb72dad20333449f8e83cfb4a" + "c8a64537a0b3a93fcde3cdad9f1ce58b"
                         + "26751f67a3cbb140b1808cf187a4f4df" + "c04b05357c5d1c0eeac4c66f9ff7f2e6")
        #expect(try AESBlock.cfbEncrypt(plaintext: plain, key: key, iv: iv) == cipher)
        #expect(try AESBlock.cfbDecrypt(ciphertext: cipher, key: key, iv: iv) == plain)
    }

    @Test func plainCFBMatchesReferenceOnRandomData() throws {
        for keyLen in [16, 24, 32] {
            for len in [0, 1, 15, 16, 17, 31, 33, 255, 4099] {
                let key = randomBytes(keyLen)
                let iv = randomBytes(16)
                let plain = randomBytes(len)
                let enc = try AESBlock.cfbEncrypt(plaintext: plain, key: key, iv: iv)
                #expect(enc == (try ReferenceCFB.crypt(plain, key: key, iv: iv, decrypt: false)))
                #expect(try AESBlock.cfbDecrypt(ciphertext: enc, key: key, iv: iv) == plain)
            }
        }
    }

    @Test func seipdEncryptMatchesReferenceDecrypt() throws {
        // New single-cryptor encrypt, old per-block NoResync decrypt + MDC.
        for len in [0, 1, 13, 16, 100, 65_537] {
            let key = randomBytes(32)
            let inner = randomBytes(len)
            let body = try SEDEncrypt.encrypt(inner: inner, sessionKey: key, symAlgoID: 9, useMDC: true)
            #expect(body.first == 0x01)
            let plain = try ReferenceCFB.openPGPDecrypt(Array(body.dropFirst()), key: key, resync: false)
            #expect(plain[16] == plain[14] && plain[17] == plain[15])
            #expect(Data(plain[18..<(18 + len)]) == inner)
            #expect(Array(plain[(18 + len)..<(20 + len)]) == [0xD3, 0x14])
            let mdc = Data(Insecure.SHA1.hash(data: Data(plain[..<(plain.count - 20)])))
            #expect(Data(plain.suffix(20)) == mdc)
        }
    }

    @Test func seipdDecryptAcceptsReferenceEncrypt() throws {
        // Old per-block encrypt, new single-cryptor decrypt (incl. a
        // multi-block body sliced out of a larger buffer).
        for len in [0, 1, 17, 4096, 1_048_579] {
            let key = randomBytes(32)
            let inner = randomBytes(len)
            let body = try ReferenceCFB.seipdEncrypt(inner: inner, key: key)
            #expect(try SEDDecrypt.decrypt(sedBody: body, sessionKey: key, symAlgoID: 9, expectMDC: true) == inner)
            let framed = Data([0xAA, 0xBB]) + body
            let slice = framed[(framed.startIndex + 2)...]
            let out = try SEDDecrypt.decrypt(sedBody: slice, sessionKey: key, symAlgoID: 9, expectMDC: true)
            #expect(out == inner)
            #expect(out.startIndex == 0)
        }
    }

    @Test func legacyResyncEncryptMatchesReference() throws {
        // Tag 9 encrypt is test-only (decrypt refuses it) but must stay a
        // correct RFC 4880 resync CFB so the refusal tests stay meaningful.
        let key = randomBytes(16)
        let inner = randomBytes(77)
        let body = try SEDEncrypt.encrypt(inner: inner, sessionKey: key, symAlgoID: 7, useMDC: false)
        let plain = try ReferenceCFB.openPGPDecrypt(Array(body), key: key, resync: true)
        #expect(plain[16] == plain[14] && plain[17] == plain[15])
        #expect(Data(plain[18...]) == inner)
    }

    @Test func badCheckOctetsRejected() throws {
        let key = randomBytes(32)
        var body = try SEDEncrypt.encrypt(inner: randomBytes(40), sessionKey: key, symAlgoID: 9, useMDC: true)
        body[body.startIndex + 1 + 16] ^= 0x01 // first check octet ciphertext
        #expect(throws: AESError.self) {
            _ = try SEDDecrypt.decrypt(sedBody: body, sessionKey: key, symAlgoID: 9, expectMDC: true)
        }
    }

    @Test func fileBlockRoundtripThroughSlices() throws {
        // FileUpload.decryptBlock parses with parseSlices; the literal
        // payload must come back zero-based and intact.
        let key = randomBytes(FileUpload.sessionKeyLength)
        let plain = randomBytes(300_001)
        let packet = try FileUpload.encryptBlock(plain, contentKey: key)
        let back = try FileUpload.decryptBlock(packet, contentKey: key)
        #expect(back == plain)
        #expect(back.startIndex == 0)
    }

    @Test func seipdPacketStreamsPartsLikeOneInner() throws {
        // seipdPacket(parts) == tag 18 framing of encrypt(parts joined), and
        // LiteralPacket.header + data == LiteralPacket.build(data).
        let key = randomBytes(32)
        let data = randomBytes(9_000)
        let header = LiteralPacket.header(dataCount: data.count, filename: "a.bin", date: 7)
        #expect(header + data == LiteralPacket.build(data: data, filename: "a.bin", date: 7))
        let packet = try SEDEncrypt.seipdPacket(innerParts: [header, data], sessionKey: key, symAlgoID: 9)
        let parsed = try PGPPackets.parse(packet)
        #expect(parsed.count == 1 && parsed[0].tag == 18)
        let inner = try SEDDecrypt.decrypt(sedBody: parsed[0].body, sessionKey: key, symAlgoID: 9, expectMDC: true)
        #expect(inner == header + data)
        #expect(try SEDDecrypt.literalData(inner) == data)
    }

    @Test func parseKeepsZeroBasedBodies() throws {
        let raw = PGPPacketsEncode.packet(tag: 11, body: Data([1, 2, 3]))
            + PGPPacketsEncode.packet(tag: 2, body: Data(repeating: 7, count: 300))
        let parsed = try PGPPackets.parse(raw)
        #expect(parsed.map(\.tag) == [11, 2])
        #expect(parsed.allSatisfy { $0.body.startIndex == 0 })
        let slices = try PGPPackets.parseSlices(raw)
        #expect(slices.map(\.body) == parsed.map(\.body))
    }
}
