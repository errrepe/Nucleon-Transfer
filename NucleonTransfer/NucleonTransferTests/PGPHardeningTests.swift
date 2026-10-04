// Nucleon Transfer — F8.1-S3 PGP hardening suite (Swift Testing).
// Tag 9 (SED without MDC) rejection, MDC tamper detection, constant-time
// compare, and SHA-2-only signature hashes. Offline; throwaway keys only.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

private struct Fixture {
    let priv = Curve25519.KeyAgreement.PrivateKey()
    let fp = Data((0..<20).map { UInt8($0) })
    let oid = Data([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x00])

    var recipient: EncryptRecipient {
        EncryptRecipient(publicPoint: priv.publicKey.rawRepresentation, fingerprint: fp,
                         curveOIDBody: oid, kdfHash: 8, kdfCipher: 9)
    }

    var candidate: DecryptCandidate {
        DecryptCandidate(scalarLE: priv.rawRepresentation, fingerprint: fp,
                         kdfHash: 8, kdfCipher: 9, curveOIDBody: oid)
    }
}

struct ConstantTimeEqualsTests {
    @Test func equalAndUnequal() {
        #expect(constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 3])))
        #expect(constantTimeEquals(Data(), Data()))
        #expect(!constantTimeEquals(Data([1, 2, 3]), Data([1, 2, 4])))
        #expect(!constantTimeEquals(Data([0x80, 2, 3]), Data([0, 2, 3])))
        #expect(!constantTimeEquals(Data([1, 2, 3]), Data([1, 2])))
    }

    @Test func worksOnSlices() {
        // MDC compare passes a Data slice (non-zero startIndex).
        let whole = Data([9, 9, 1, 2, 3])
        #expect(constantTimeEquals(Data([1, 2, 3]), whole.suffix(3)))
        #expect(!constantTimeEquals(Data([1, 2, 3]), whole.prefix(3)))
    }
}

struct SEDHardeningTests {
    @Test func tag9MessageRejected() throws {
        let f = Fixture()
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data("no-mdc".utf8), recipient: f.recipient, cipher: 9, useMDC: false
        )
        #expect(try PGPPackets.parse(try Armor.decode(armored)).map(\.tag) == [1, 9])
        #expect(throws: SEDError.integrityProtectionRequired) {
            _ = try MessageDecrypt.decrypt(armored: armored, candidates: [f.candidate])
        }
    }

    @Test func tag9AlongsideTag18Rejected() throws {
        // A stray tag 9 next to a valid tag 18 still fails the message: no
        // packet-order games that could steer a decoder to the unprotected one.
        let f = Fixture()
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data("mixed".utf8), recipient: f.recipient, cipher: 9, useMDC: true
        )
        let packets = try PGPPackets.parse(try Armor.decode(armored))
        #expect(packets.map(\.tag) == [1, 18])
        var raw = PGPPacketsEncode.packet(tag: 1, body: packets[0].body)
        raw.append(PGPPacketsEncode.packet(tag: 18, body: packets[1].body))
        raw.append(PGPPacketsEncode.packet(tag: 9, body: Data(packets[1].body.dropFirst())))
        #expect(throws: SEDError.integrityProtectionRequired) {
            _ = try MessageDecrypt.decrypt(armored: Armor.encode(raw), candidates: [f.candidate])
        }
        // Sanity: the untouched message decrypts.
        #expect(try MessageDecrypt.decrypt(armored: armored, candidates: [f.candidate]) == Data("mixed".utf8))
    }

    @Test func sedDecryptRefusesExpectMDCFalse() throws {
        // Even a well-formed tag 18 body is refused if a caller asks for the
        // legacy no-MDC path.
        let session = Data(repeating: 0x42, count: 32)
        let body = try SEDEncrypt.encrypt(inner: LiteralPacket.build(data: Data("x".utf8)),
                                          sessionKey: session, symAlgoID: 9, useMDC: true)
        #expect(throws: SEDError.integrityProtectionRequired) {
            _ = try SEDDecrypt.decrypt(sedBody: body, sessionKey: session, symAlgoID: 9, expectMDC: false)
        }
    }

    @Test func mdcTamperInDataRejected() throws {
        // Flip a ciphertext byte in the literal data region (not the MDC):
        // the plaintext changes and the MDC must catch it.
        let session = Data(repeating: 0x24, count: 32)
        let inner = LiteralPacket.build(data: Data(String(repeating: "payload-", count: 16).utf8))
        let body = try SEDEncrypt.encrypt(inner: inner, sessionKey: session, symAlgoID: 9, useMDC: true)
        #expect(try SEDDecrypt.decrypt(sedBody: body, sessionKey: session, symAlgoID: 9, expectMDC: true) == inner)
        var tampered = body
        let at = tampered.index(tampered.startIndex, offsetBy: 1 + 18 + 40) // version + prefix + data
        tampered[at] ^= 0x01
        #expect(throws: SEDError.mdcMismatch) {
            _ = try SEDDecrypt.decrypt(sedBody: tampered, sessionKey: session, symAlgoID: 9, expectMDC: true)
        }
    }

    @Test func mdcTamperInArmoredMessageRejected() throws {
        let f = Fixture()
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data(String(repeating: "secret-", count: 12).utf8),
            recipient: f.recipient, cipher: 9, useMDC: true
        )
        let packets = try PGPPackets.parse(try Armor.decode(armored))
        var sed = packets[1].body
        sed[sed.index(sed.startIndex, offsetBy: 1 + 18 + 30)] ^= 0x80
        var raw = PGPPacketsEncode.packet(tag: 1, body: packets[0].body)
        raw.append(PGPPacketsEncode.packet(tag: 18, body: sed))
        #expect(throws: SEDError.mdcMismatch) {
            _ = try MessageDecrypt.decrypt(armored: Armor.encode(raw), candidates: [f.candidate])
        }
    }
}

struct SignatureHashPolicyTests {
    private let seed = Data((0..<32).map { UInt8($0) })
    private let fp = Data((0..<20).map { UInt8(0xA0 &+ $0) })
    private let data = Data("signed-bytes".utf8)

    private func signedBody(hashAlgo: UInt8) throws -> Data {
        try DetachedSign.signatureBody(
            data: data, signerSeedLE: seed, signerKeyID: Data(fp.suffix(8)),
            signerFingerprint: fp, hashAlgo: hashAlgo, createdAt: 1_700_000_000
        )
    }

    private var pub: Data {
        get throws { try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation }
    }

    @Test(arguments: [UInt8(1), UInt8(2)])
    func weakHashRejected(hashAlgo: UInt8) throws {
        // A cryptographically valid Ed25519 signature over an MD5/SHA-1
        // digest must still be refused.
        let sig = try DetachedSig.parse(body: try signedBody(hashAlgo: hashAlgo))
        #expect(sig.hashAlgo == hashAlgo)
        let key = try pub
        do {
            _ = try sig.verify(data: data, signerPointMPI: key)
            Issue.record("weak hash \(hashAlgo) accepted")
        } catch SigError.weakHash(let id) {
            #expect(id == hashAlgo)
        }
    }

    @Test(arguments: [UInt8(8), UInt8(9), UInt8(10), UInt8(11)])
    func sha2Accepted(hashAlgo: UInt8) throws {
        let sig = try DetachedSig.parse(body: try signedBody(hashAlgo: hashAlgo))
        let key = try pub
        #expect(try sig.verify(data: data, signerPointMPI: key) == true)
        #expect(try sig.verify(data: Data("other".utf8), signerPointMPI: key) == false)
    }
}
