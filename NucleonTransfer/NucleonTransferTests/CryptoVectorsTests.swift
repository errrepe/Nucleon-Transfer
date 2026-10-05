// Nucleon Transfer — offline crypto vector suite (Swift Testing).
// Every vector is independently verified: RFC text, Python reference
// implementations, or synthetic interop fixtures. NO network, NO secrets.
// Slow ops (cost-10 bcrypt ~0.5s debug) are kept to a minimum.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

private func HX(_ s: String) -> Data {
    var d = Data()
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return d
}

private func HEX(_ d: Data) -> String {
    d.map { String(format: "%02x", $0) }.joined()
}

struct CryptoVectorsTests {
    @Test func expandHashLength() {
        #expect(ExpandHash.expand(Data("abc".utf8)).count == 256)
    }

    @Test func usernameCleaner() {
        #expect(UsernameCleaner.clean("User.Name-_X") == "usernamex")
    }

    @Test func dotSlashBase64() {
        #expect(DotSlashBase64.encode(Data([0xFF, 0x00, 0xAB])) == "9uAp")
    }

    @Test func bigUIntMulExact() {
        // Verified against Python integers. toDataLE is little-endian, so the
        // expected big-endian hex is byte-reversed for comparison.
        let a = BigUInt(dataLE: Data(HX("5555555555555555AAAAAAAAAAAAAAAA0FEDCBA987654321123456789ABCDEF0").reversed()))
        let b = BigUInt(dataLE: Data(HX("4444444444444444333333333333333322222222222222221111111111111111").reversed()))
        let p = BigUInt.mul(a, b)
        let exp = Data(HX("16c16c16c16c16c17d27d27d27d27d279dd9031c241b00d59d6480f2b9d6480a97530eca8641fdba9d0369d0369d036afdb97530eca86420fec94f918f48bdf0").reversed())
        #expect(p.toDataLE(length: 64) == exp)
    }

    @Test func bigUIntModPowExact() {
        // pow(a, 3, 2^256 - 1), verified against Python pow().
        let a = BigUInt(dataLE: Data(HX("5555555555555555AAAAAAAAAAAAAAAA0FEDCBA987654321123456789ABCDEF0").reversed()))
        let m = BigUInt(dataLE: Data(HX(String(repeating: "ff", count: 32)).reversed()))
        let r = BigUInt.modPow(a, BigUInt(limbs: [3]), m)
        let exp = Data(HX("3cc587e308a7979de889a8ab357fa91174f4220784832b68ee4535f2c5de093f").reversed())
        #expect(r.toDataLE(length: 32) == exp)
    }

    @Test func bigUIntDivmodConsistent() {
        let a = BigUInt(dataLE: Data(HX("5555555555555555AAAAAAAAAAAAAAAA0FEDCBA987654321123456789ABCDEF0").reversed()))
        let m = BigUInt(dataLE: Data(HX(String(repeating: "ff", count: 32)).reversed()))
        let t = BigUInt.mul(BigUInt.mul(a, a), a)
        let (q, r) = BigUInt.divmod(t, m)
        #expect(BigUInt.add(BigUInt.mul(q, m), r) == t)
    }

    @Test func bcryptVectors() throws {
        let h = ProtonBcryptHasher()
        // Cost-6 canonical (ground truth: Python reference bcrypt).
        let v1 = try h.hash(password: Data("password".utf8), dotSlashSalt: "$2a$06$DCq7YPn5Rq63x1Lad4cll.")
        #expect(String(data: v1, encoding: .utf8) == "$2a$06$DCq7YPn5Rq63x1Lad4cll.kD3zZ845LsvMekyowTQk2VNmbDdQsWO")
        // Cost-10 ASCII + UTF-8 (verified vs Python reference bcrypt).
        // NOTE: hasher mirrors go (versions a/y only), so vectors use $2a$.
        let v2 = try h.hash(password: Data("hello".utf8), dotSlashSalt: "$2a$10$abcdefghijklmnopqrstuu")
        #expect(String(data: v2, encoding: .utf8) == "$2a$10$abcdefghijklmnopqrstuubpco9BuLQZBZtn/gwh0hqaJSVqpe2FC")
        let v3 = try h.hash(password: Data("pässwörd".utf8), dotSlashSalt: "$2y$10$abcdefghijklmnopqrstuu")
        #expect(String(data: v3, encoding: .utf8) == "$2y$10$abcdefghijklmnopqrstuunYspUDVwxKwnshT7FzjzjwI57RV2KKa")
    }

    @Test(arguments: [
        // jBCrypt TestBCrypt canonical vectors (cost 6).
        ("a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"),
        ("abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu",
         "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"),
    ])
    func bcryptCanonicalVectors(password: String, salt: String, expected: String) throws {
        let out = try ProtonBcryptHasher().hash(password: Data(password.utf8), dotSlashSalt: salt)
        #expect(String(decoding: out, as: UTF8.self) == expected)
    }

    @Test func s2kIteratedSHA256() throws {
        // Iterated (t=3), SHA-256, 8-byte salt, count 65536 (0x60).
        // Reference: independent Python implementation.
        let spec = Data([3, 8]) + HX("0011223344556677") + Data([0x60])
        let (key, _) = try S2K.derive(spec: spec, passphrase: Data("s2k-test-password".utf8), keyLength: 32)
        #expect(HEX(try PGPHash.digest(id: 8, key)) == "fe374027e9a56b96b530a248d0bd29f168b9e0414c311712c7151ee5b8425411")
    }

    @Test func aesKeyWrapRFC3394() throws {
        // RFC 3394 §4.1 unwrap.
        let kek = HX("000102030405060708090A0B0C0D0E0F")
        let ct = HX("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
        let pt = try AESKeyWrap.unwrap(ct, kek: kek)
        #expect(HEX(pt) == "00112233445566778899aabbccddeeff")
        let rt = try AESKeyWrap.unwrap(try AESKeyWrap.wrap(pt, kek: kek), kek: kek)
        #expect(rt == pt)
        do {
            _ = try AESKeyWrap.unwrap(HX("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE4"), kek: kek)
            Issue.record("tampered wrap accepted")
        } catch { /* expected */ }
    }

    @Test func ecdhInteropSynthetic() throws {
        // Synthetic PKESK built by Python (cryptography lib): X25519 agree +
        // RFC 6637 KDF (SHA-256, param WITHOUT DER tag) + AES-KW.
        // Fresh throwaway keys; the test self-validates via checksum.
        let pkesk = try PKESK_ECDH.parse(body: HX(
            "0300000000000000001201074090b19a727d8321f55034be124d28b091ecfa81c181f0adc44ccf8a368441965730f3a7867c45428d78ffa26d56cb6519f9a64e2e90f31d0df2df2464ef107a9cb528b6157947a78b51c8ecd2eb73e9ae03"
        ))
        let (cf, sess) = try ECDHDecrypt.decrypt(
            pkesk,
            privateScalarLE: HX("785c6a52419fb084e2ad88e615f3f1be66ecadc3678a0b21d48fccdb58183e74"),
            curveOIDBody: HX("2b06010401da470f00"),
            fingerprint: HX("00112233445566778899aabbccddeeff00112233"),
            kdfHash: 8, kdfCipher: 9
        )
        #expect(cf == 0x09)
        #expect(HEX(sess) == "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    }

    @Test func ed25519DetachedRoundtrip() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pub = key.publicKey.rawRepresentation
        let data = Data("nucleon-transfer".utf8)
        let time: UInt32 = 1_700_000_000
        let hashed: [UInt8] = [0x02, 0x04,
            UInt8((time >> 24) & 0xFF), UInt8((time >> 16) & 0xFF),
            UInt8((time >> 8) & 0xFF), UInt8(time & 0xFF)]
        var body = Data([0x04, 0x00, 0x16, 0x0A])
        body.append(UInt8(hashed.count >> 8)); body.append(UInt8(hashed.count & 0xFF))
        body.append(contentsOf: hashed)
        let hashedEnd = body.count
        body.append(contentsOf: [0x00, 0x00])
        var trailer = Data(body.prefix(hashedEnd))
        trailer.append(contentsOf: [0x04, 0xFF])
        let hl = UInt32(hashedEnd)
        trailer.append(contentsOf: [UInt8((hl >> 24) & 0xFF), UInt8((hl >> 16) & 0xFF), UInt8((hl >> 8) & 0xFF), UInt8(hl & 0xFF)])
        var pre = data; pre.append(trailer)
        let digest = Data(SHA512.hash(data: pre))
        let sig = try key.signature(for: digest)
        body.append(contentsOf: digest.prefix(2))
        body.append(contentsOf: [0x02, 0x00])
        body.append(contentsOf: sig)
        let parsed = try DetachedSig.parse(body: body)
        #expect(try parsed.verify(data: data, signerPointMPI: pub))
        #expect(!(try parsed.verify(data: Data("tampered!".utf8), signerPointMPI: pub)))
    }

    @Test func fingerprintV4Synthetic() throws {
        // Synthetic v4 EdDSA public body; reference: independent Python hashlib.
        let publicBody = HX("04" + "01020304" + "16" + "09" + "2b06010401da470f01" + "0107" + "40" + String(repeating: "ab", count: 32))
        #expect(HEX(try PGPFingerprint.v4(publicBody: publicBody)) == "d579b2eadb5b4eb52fd370a757604d5cd1a491c2")
    }

    @Test func gpgSkeskSeipdFlow() throws {
        // GnuPG-made SKESK + SEIPDv1 (tag 18, version octet 0x01) with a ZIP-
        // compressed payload ("hello-gpg-test", passphrase "test123" —
        // throwaway fixtures). Decrypt + MDC verify must succeed; literal
        // extraction must fail LOUDLY with unsupportedCompression (raw
        // DEFLATE needs a vendored inflater; Proton messages are literals).
        let raw = HX("8c0d0409030a70fb415ce0373da660d243018bdaab4b0a73bba3376ac661054c79fa82b5487a24ab57ae728fbc5962a4c494551a6ed576ea5c0afa0a43b9b2578196edc5839e1cd5c3f048d49f5b57e297176ba3")
        let pkts = try PGPPackets.parse(raw)
        let skesk = try #require(pkts.first(where: { $0.tag == 3 }).map(\.body))
        let sed = try #require(pkts.first(where: { $0.tag == 18 }).map(\.body))
        let cipher = skesk[skesk.index(skesk.startIndex, offsetBy: 1)]
        let spec = Data(skesk[skesk.index(skesk.startIndex, offsetBy: 2)...])
        let (sess, _) = try S2K.derive(spec: spec, passphrase: Data("test123".utf8), keyLength: Int(try PGPSymmetricAlgo.keyLength(id: cipher)))
        let inner = try SEDDecrypt.decrypt(sedBody: sed, sessionKey: sess, symAlgoID: cipher, expectMDC: true)
        do {
            _ = try SEDDecrypt.literalData(inner)
            Issue.record("expected unsupportedCompression")
        } catch let e as SEDError {
            #expect(e == .unsupportedCompression(1))
        }
    }

    @Test func craftedSeipdRoundtrip() throws {
        // Self-made SEIPDv1 (version octet + NoResync CFB + MDC over full
        // prefix), independently verified by GnuPG decrypting it to
        // "craft-test-ok". Passphrase "craftpw123" is a throwaway fixture.
        let raw = HX("c30d0409030a62e7512e04b9743c60d23e017313c36bc99bf7a2e6c7a00f9993cf369289a0892653778cc0d1e156bcbe19f34e911699411d36bf98125e6065332b661a964bde8f8ab8f8bfbcd1951e")
        let pkts = try PGPPackets.parse(raw)
        let skesk = try #require(pkts.first(where: { $0.tag == 3 }).map(\.body))
        let sed = try #require(pkts.first(where: { $0.tag == 18 }).map(\.body))
        let cipher = skesk[skesk.index(skesk.startIndex, offsetBy: 1)]
        let spec = Data(skesk[skesk.index(skesk.startIndex, offsetBy: 2)...])
        let (sess, _) = try S2K.derive(spec: spec, passphrase: Data("craftpw123".utf8), keyLength: Int(try PGPSymmetricAlgo.keyLength(id: cipher)))
        let inner = try SEDDecrypt.decrypt(sedBody: sed, sessionKey: sess, symAlgoID: cipher, expectMDC: true)
        #expect(try SEDDecrypt.literalData(inner) == Data("craft-test-ok".utf8))
    }

    @Test func ecdhEncryptGoldenVector() throws {
        // Deterministic PKESK (fixed recipient + ephemeral scalars, AES-256
        // session, SHA-256/AES-128 KDF): ECDHEncrypt output must byte-match
        // this golden value AND decrypt back via ECDHDecrypt. The same code
        // path was verified against GnuPG 2.5 (gpg decrypted our messages
        // to a live cv25519 subkey: tag 18 clean, tag 9 byte-exact).
        let scalarLE = HX("785c6a52419fb084e2ad88e615f3f1be66ecadc3678a0b21d48fccdb58183e74")
        let pub = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalarLE).publicKey.rawRepresentation
        let fp = HX("5d974b037cf11a1260fcaa752a206b1b2802c517")
        let oid = HX("2b060104019755010501")
        let session = HX("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        let body = try ECDHEncrypt.encrypt(
            sessionKey: session, cipherFunc: 9,
            recipientPublicPoint: pub, recipientFingerprint: fp,
            curveOIDBody: oid, kdfHash: 8, kdfCipher: 7,
            ephemeralPrivateLE: HX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        )
        #expect(HEX(body) == "032a206b1b2802c517120107408f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f304f65e7fbb729a404d42b11e37ae5b66cd93acac37d1301ae08965a7c57ffcf982466f886dc9345d67c0f071d62370ffc")
        let pkesk = try PKESK_ECDH.parse(body: body)
        #expect(pkesk.keyID == 0x2A206B1B2802C517) // fp tail, as live-verified
        let (cf, sess) = try ECDHDecrypt.decrypt(
            pkesk, privateScalarLE: scalarLE, curveOIDBody: oid,
            fingerprint: fp, kdfHash: 8, kdfCipher: 7
        )
        #expect(cf == 9)
        #expect(sess == session)
    }

    @Test func sedTag9AES128Rejected() throws {
        // F8.1-S3: was a tag 9 (resync CFB, no MDC) roundtrip. Decrypting
        // SED without integrity protection is now refused (EFAIL class),
        // even when the session key is correct.
        let session = HX("00112233445566778899aabbccddeeff")
        let inner = LiteralPacket.build(data: Data("tag9-roundtrip-ok".utf8))
        let body = try SEDEncrypt.encrypt(inner: inner, sessionKey: session, symAlgoID: 7, useMDC: false)
        #expect(throws: SEDError.integrityProtectionRequired) {
            _ = try SEDDecrypt.decrypt(sedBody: body, sessionKey: session, symAlgoID: 7, expectMDC: false)
        }
    }

    @Test func sedEncryptDecryptTag18AES256() throws {
        // Tag 18 v1 (NoResync CFB + MDC) roundtrip with AES-256; tampering
        // must fail loudly with mdcMismatch.
        let session = HX("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        let inner = LiteralPacket.build(data: Data("tag18-roundtrip-ok".utf8))
        let body = try SEDEncrypt.encrypt(inner: inner, sessionKey: session, symAlgoID: 9, useMDC: true)
        #expect(body.first == 0x01)
        let back = try SEDDecrypt.decrypt(sedBody: body, sessionKey: session, symAlgoID: 9, expectMDC: true)
        #expect(try SEDDecrypt.literalData(back) == Data("tag18-roundtrip-ok".utf8))
        var tampered = body
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        do {
            _ = try SEDDecrypt.decrypt(sedBody: tampered, sessionKey: session, symAlgoID: 9, expectMDC: true)
            Issue.record("tampered MDC accepted")
        } catch let e as SEDError {
            #expect(e == .mdcMismatch)
        }
    }

    @Test func messageEncryptRoundtripTag18() throws {
        // Full armored message (PKESK + SEIPDv1, AES-256) self-roundtrip.
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let fp = HX("00112233445566778899aabbccddeeff00112233")
        let oid = HX("2b06010401da470f00")
        let recipient = EncryptRecipient(
            publicPoint: priv.publicKey.rawRepresentation, fingerprint: fp,
            curveOIDBody: oid, kdfHash: 8, kdfCipher: 9
        )
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data("hello-nucleon-18".utf8), recipient: recipient, cipher: 9, useMDC: true
        )
        let candidate = DecryptCandidate(
            scalarLE: priv.rawRepresentation, fingerprint: fp,
            kdfHash: 8, kdfCipher: 9, curveOIDBody: oid
        )
        #expect(try MessageDecrypt.decrypt(armored: armored, candidates: [candidate]) == Data("hello-nucleon-18".utf8))
    }

    @Test func messageTag9Rejected() throws {
        // F8.1-S3: was a full armored PKESK + SED (tag 9, AES-128)
        // self-roundtrip. The message still encrypts as [1, 9], but
        // MessageDecrypt now refuses it with the right key.
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let fp = HX("ffeeddccbbaa99887766554433221100ffeeddcc")
        let oid = HX("2b06010401da470f00")
        let recipient = EncryptRecipient(
            publicPoint: priv.publicKey.rawRepresentation, fingerprint: fp,
            curveOIDBody: oid, kdfHash: 8, kdfCipher: 7
        )
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data("hello-nucleon-9".utf8), recipient: recipient, cipher: 7, useMDC: false
        )
        let raw = try Armor.decode(armored)
        #expect(try PGPPackets.parse(raw).map(\.tag) == [1, 9])
        let candidate = DecryptCandidate(
            scalarLE: priv.rawRepresentation, fingerprint: fp,
            kdfHash: 8, kdfCipher: 7, curveOIDBody: oid
        )
        #expect(throws: SEDError.integrityProtectionRequired) {
            _ = try MessageDecrypt.decrypt(armored: armored, candidates: [candidate])
        }
    }

    @Test func nameEncryptParentKeyringRule() throws {
        // Names encrypt to the PARENT keyring: a name encrypted with the
        // parent recipient decrypts with the parent candidate only (never
        // the node's own), and the PKESK keyID is the parent fp tail.
        let parentPriv = Curve25519.KeyAgreement.PrivateKey()
        let parentFP = HX("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let oid = HX("2b06010401da470f00")
        let parentR = EncryptRecipient(
            publicPoint: parentPriv.publicKey.rawRepresentation, fingerprint: parentFP,
            curveOIDBody: oid, kdfHash: 8, kdfCipher: 9
        )
        let otherPriv = Curve25519.KeyAgreement.PrivateKey()
        let otherC = DecryptCandidate(
            scalarLE: otherPriv.rawRepresentation,
            fingerprint: HX("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            kdfHash: 8, kdfCipher: 9, curveOIDBody: oid
        )
        let parentC = DecryptCandidate(
            scalarLE: parentPriv.rawRepresentation, fingerprint: parentFP,
            kdfHash: 8, kdfCipher: 9, curveOIDBody: oid
        )
        let armored = try MessageEncrypt.encryptName("Photos", parentRecipient: parentR)
        #expect(try MessageDecrypt.decrypt(armored: armored, candidates: [parentC]) == Data("Photos".utf8))
        do {
            _ = try MessageDecrypt.decrypt(armored: armored, candidates: [otherC])
            Issue.record("name decrypted with non-parent key")
        } catch { /* expected */ }
        let raw = try Armor.decode(armored)
        let pkeskBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 1 }).map(\.body))
        #expect(try PKESK_ECDH.parse(body: pkeskBody).keyID == 0xAAAAAAAAAAAAAAAA)
    }

    @Test func armorEncodeRoundtrip() throws {
        // Armor.encode is the exact inverse of Armor.decode (incl. CRC24).
        let raw = Data((0..<256).map { UInt8($0) })
        let enc = Armor.encode(raw)
        #expect(enc.hasPrefix("-----BEGIN PGP MESSAGE-----\n"))
        #expect(enc.hasSuffix("-----END PGP MESSAGE-----\n"))
        #expect(try Armor.decode(enc) == raw)
    }

    // MARK: - F4.2 folder creation

    @Test func cfbEncryptRoundtrip() throws {
        // AESBlock.cfbEncrypt is the exact inverse of cfbDecrypt, including
        // trailing partial blocks.
        let key = HX("00112233445566778899aabbccddeeff")
        let iv = HX("0102030405060708090a0b0c0d0e0f10")
        for len in [1, 15, 16, 17, 31, 32, 33, 53] {
            let plain = Data((0..<len).map { UInt8($0 & 0xFF) })
            let enc = try AESBlock.cfbEncrypt(plaintext: plain, key: key, iv: iv)
            #expect(try AESBlock.cfbDecrypt(ciphertext: enc, key: key, iv: iv) == plain)
        }
    }

    @Test func nameHashVectors() throws {
        // GetNameHash parity vectors from henrybear327/go-proton-api
        // link_file_type_test.go (key = 32 x 'a', NFC names — verified the
        // expected digests are NFC, matching our precomposedString mapping).
        let key = Data(repeating: 0x61, count: 32)
        let vectors: [(String, String)] = [
            ("garçon", "02ef4861a4b9f833aa104a8210f5eb338e231c9532d9c2551aaf76bafb511208"),
            ("apă", "fd80de16c11bdcea2783274f6b7f334093ef95d58c7381c615005614ed77dc94"),
            ("bala", "35733f41071d4997876b5bb54acc1d587646bdf1251f9b9c49ee9dc023a69962"),
            ("țânțar", "4f4dee0cd87928027982c6ca280d2c7661073082ed46a82c111880126b0c3e14"),
            ("întuneric", "6bed2bff136e165ad54d0a2a9a549481c88aca55d567c93123e0e5b876c291b2"),
            ("mädchen", "2b112b1b7ac4fd9dae5a2acd8fcf2e905bd92a06a95dc4495fa012bda93e8607"),
            ("integrationTestImage.png", "2e700ef3b52379a9277ac48bcfc5dff56e6927274267a0df4673f4f21e5d04d6"),
        ]
        for (name, exp) in vectors {
            #expect(NameHash.hex(name: name, hashKey: key) == exp)
        }
    }

    @Test func detachedSignRoundtrip() throws {
        // DetachedSign output parses via DetachedSig and verifies; tampering
        // or a wrong signer fails. Fixed seed + time => fully deterministic.
        let seed = HX("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let pub = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation
        let fp = HX("00112233445566778899aabbccddeeff00112233")
        let keyID = fp.suffix(8)
        let data = Data("node-passphrase-bytes".utf8)
        let armored = try DetachedSign.sign(
            data: data, signerSeedLE: seed, signerKeyID: Data(keyID),
            signerFingerprint: fp, hashAlgo: 10, createdAt: 1_700_000_000
        )
        #expect(armored.hasPrefix("-----BEGIN PGP SIGNATURE-----"))
        let raw = try Armor.decode(armored)
        let packets = try PGPPackets.parse(raw)
        #expect(packets.map(\.tag) == [2])
        // Proton hashed set: creation-critical + issuer + salt notation +
        // issuer-fingerprint (hlen 109); the server requires the notation.
        let body = packets[0].body
        let hlen = (Int(body[body.startIndex + 4]) << 8) | Int(body[body.startIndex + 5])
        #expect(hlen == 109)
        let hashed = Data(body[(body.startIndex + 6)..<(body.startIndex + 6 + hlen)])
        #expect(hashed[hashed.startIndex + 1] == 0x82) // creation-time CRITICAL
        let hashedHex = hashed.map { String(format: "%02x", $0) }.joined()
        #expect(hashedHex.contains("73616c74406e6f746174696f6e732e6f70656e7067706a732e6f7267")) // salt@notations.openpgpjs.org
        #expect(Data(hashed.suffix(21)) == Data([0x04]) + fp) // issuer-fp packet
        // Same input + same time => bodies differ only in the fresh salt.
        let armored2 = try DetachedSign.sign(
            data: data, signerSeedLE: seed, signerKeyID: Data(keyID),
            signerFingerprint: fp, hashAlgo: 10, createdAt: 1_700_000_000
        )
        #expect(armored != armored2)
        let sig = try DetachedSig.parse(body: packets[0].body)
        #expect(sig.publicAlgo == 22)
        #expect(try sig.verify(data: data, signerPointMPI: pub) == true)
        #expect(try sig.verify(data: data, signerPointMPI: pub) == true)
        #expect(try sig.verify(data: Data("tampered".utf8), signerPointMPI: pub) == false)
        let otherPub = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        #expect(try sig.verify(data: data, signerPointMPI: otherPub) == false)
    }

    @Test func nodeKeyGenRoundtrip() throws {
        // Generated node keys parse + unlock through the SAME path as live
        // keys (SecretKeyPacket.parse + SecretKeyUnlock + public-match), with
        // fingerprints matching PGPFingerprint.v4 over the parsed public body.
        let pass = Data("test-node-passphrase".utf8)
        let gen = try NodeKeyGen.generate(passphrase: pass, createdAt: 1_700_000_000)
        #expect(gen.edSeed.count == 32)
        #expect(gen.xScalarLE.count == 32)
        let raw = try Armor.decode(gen.armoredKey)
        let packets = try PGPPackets.parse(raw)
        // Full transferable key like official creates: primary + UID +
        // self-cert + subkey + binding (bare 5+7 blobs are rejected server-side).
        #expect(packets.map(\.tag) == [5, 13, 2, 7, 2])
        #expect(String(data: packets[1].body, encoding: .utf8) == "Drive key <noreply@protonmail.com>")
        let edPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: gen.edSeed).publicKey.rawRepresentation

        let ed = try SecretKeyPacket.parse(body: packets[0].body)
        #expect(ed.publicAlgo == 22)
        #expect(ed.s2kUsage == 254)
        #expect(ed.symmetricAlgo == 9)
        let edPlain = try SecretKeyUnlock.decrypt(ed, passphrase: pass)
        #expect(try SecretKeyUnlock.secretScalar(plaintext: edPlain) == gen.edSeed)
        #expect(SecretKeyVerify.ed25519PublicMatches(seed: gen.edSeed, pointMPI: ed.publicPoint ?? Data()))
        #expect(try PGPFingerprint.v4(publicBody: ed.publicBody) == gen.edFingerprint)

        let x = try SecretKeyPacket.parse(body: packets[3].body)
        #expect(x.publicAlgo == 18)
        #expect(x.kdfHash == 8)
        #expect(x.kdfCipher == 7)
        #expect(x.curveOID == NodeKeyGen.ecdhOID)
        let xPlain = try SecretKeyUnlock.decrypt(x, passphrase: pass)
        #expect(try SecretKeyUnlock.ecdhScalar(plaintext: xPlain) == gen.xScalarLE)
        #expect(SecretKeyVerify.x25519PublicMatches(scalar: gen.xScalarLE, pointMPI: x.publicPoint ?? Data()))
        #expect(try PGPFingerprint.v4(publicBody: x.publicBody) == gen.xFingerprint)

        // Wrong passphrase must fail loudly.
        do {
            _ = try SecretKeyUnlock.decrypt(ed, passphrase: Data("wrong".utf8))
            Issue.record("node key unlocked with wrong passphrase")
        } catch { /* expected */ }

        // Self-certification (0x13, SHA-256) verifies over framed primary
        // pub + framed UID with the primary point...
        let certSig = try DetachedSig.parse(body: packets[2].body)
        #expect(certSig.type == 0x13)
        #expect(certSig.hashAlgo == 8)
        let certData = DetachedSign.framedPub(ed.publicBody)
            + DetachedSign.framedUID(Data("Drive key <noreply@protonmail.com>".utf8))
        #expect(try certSig.verify(data: certData, signerPointMPI: edPoint) == true)
        // ...and the binding (0x18) over framed primary + subkey pubs.
        let bindSig = try DetachedSig.parse(body: packets[4].body)
        #expect(bindSig.type == 0x18)
        #expect(bindSig.hashAlgo == 8)
        let bindData = DetachedSign.framedPub(ed.publicBody)
            + DetachedSign.framedPub(x.publicBody)
        #expect(try bindSig.verify(data: bindData, signerPointMPI: edPoint) == true)
    }

    @Test func signedMessageRoundtrip() throws {
        // encryptSigned (OPS + literal + SIG inside) decrypts via the
        // unchanged MessageDecrypt path, and the inline signature verifies.
        let encPriv = Curve25519.KeyAgreement.PrivateKey()
        let fp = HX("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        let oid = NodeKeyGen.ecdhOID
        let recipient = EncryptRecipient(
            publicPoint: encPriv.publicKey.rawRepresentation, fingerprint: fp,
            curveOIDBody: oid, kdfHash: 8, kdfCipher: 7
        )
        let signSeed = Curve25519.Signing.PrivateKey().rawRepresentation
        let signPub = try Curve25519.Signing.PrivateKey(rawRepresentation: signSeed).publicKey.rawRepresentation
        let signFP = HX("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        let armored = try MessageEncrypt.encryptSigned(
            plaintext: Data("signed-name".utf8), recipient: recipient,
            signerSeedLE: signSeed, signerKeyID: Data(signFP.suffix(8)),
            signerFingerprint: signFP
        )
        let candidate = DecryptCandidate(
            scalarLE: encPriv.rawRepresentation, fingerprint: fp,
            kdfHash: 8, kdfCipher: 7, curveOIDBody: oid
        )
        #expect(try MessageDecrypt.decrypt(armored: armored, candidates: [candidate]) == Data("signed-name".utf8))
        // Inner packet layout must be exactly OPS + literal + SIG.
        let raw = try Armor.decode(armored)
        let sedBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 18 }).map(\.body))
        let session: Data = try {
            let pkeskBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 1 }).map(\.body))
            let (_, sess) = try ECDHDecrypt.decrypt(
                try PKESK_ECDH.parse(body: pkeskBody), privateScalarLE: candidate.scalarLE,
                curveOIDBody: oid, fingerprint: fp, kdfHash: 8, kdfCipher: 7
            )
            return sess
        }()
        let inner = try SEDDecrypt.decrypt(sedBody: sedBody, sessionKey: session, symAlgoID: 9, expectMDC: true)
        let tags = try PGPPackets.parse(inner).map(\.tag)
        #expect(tags == [4, 11, 2])
        // OPS framing must match official packets byte-for-byte: v3, class
        // 0x00, hash algo matching the SIG, signer keyID, nested=0x01
        // (live-captured Proton quirk — RFC would say 0x00, server wants 0x01).
        let opsBody = try #require(try PGPPackets.parse(inner).first(where: { $0.tag == 4 }).map(\.body))
        #expect(opsBody.count == 13)
        #expect(opsBody[opsBody.startIndex] == 0x03)
        #expect(opsBody[opsBody.startIndex + 1] == 0x00)
        #expect(opsBody[opsBody.startIndex + 2] == 0x0A)
        #expect(opsBody[opsBody.startIndex + 3] == 22)
        #expect(Data(opsBody.dropFirst(4).prefix(8)) == Data(signFP.suffix(8)))
        #expect(opsBody[opsBody.index(before: opsBody.endIndex)] == 0x01)
        let sigBody = try #require(try PGPPackets.parse(inner).first(where: { $0.tag == 2 }).map(\.body))
        let sig = try DetachedSig.parse(body: sigBody)
        #expect(try sig.verify(data: Data("signed-name".utf8), signerPointMPI: signPub) == true)
    }

    @Test func folderCreateMaterialSelfConsistent() throws {
        // Full offline mirror of the live F4.2 flow minus network: build a
        // request with synthetic parent/address keys, then consume every
        // field the way DecryptChain + the server-hash check will.
        let parentX = Curve25519.KeyAgreement.PrivateKey()
        let parentFP = HX("1111111111111111111111111111111111111111")
        let addrSeed = Curve25519.Signing.PrivateKey().rawRepresentation
        let addrFP = HX("2222222222222222222222222222222222222222")
        let parentKeys = [KeyringCache.UnlockedKey(
            keyID: "test-parent#18", algo: 18, seed: parentX.rawRepresentation,
            fingerprint: parentFP, kdfHash: 8, kdfCipher: 7, curveOIDBody: NodeKeyGen.ecdhOID
        )]
        let addressKeys = [KeyringCache.UnlockedKey(
            keyID: "test-addr#22", algo: 22, seed: addrSeed,
            fingerprint: addrFP, kdfHash: 8, kdfCipher: 9, curveOIDBody: NodeKeyGen.edOID
        )]
        let parentHashKey = Data((0..<32).map { UInt8($0) })
        let xAttrJSON = Data("{\"modificationTime\":123}".utf8)
        let (request, node) = try FolderCreate.buildRequest(
            name: "NT-Test", parentLinkID: "parent", parentKeys: parentKeys,
            parentHashKey: parentHashKey, addressKeys: addressKeys,
            signatureAddress: "test@proton.me", xAttrPlaintext: xAttrJSON
        )
        let parentCands = parentKeys.compactMap(\.candidate)
        #expect(parentCands.count == 1)

        // NodePassphrase decrypts with the parent candidate...
        let passBytes = try MessageDecrypt.decrypt(armored: request.nodePassphrase, candidates: parentCands)
        #expect(Data(passBytes) == node.passphrase)
        // ...and its detached signature verifies with the address point.
        let addrPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: addrSeed).publicKey.rawRepresentation
        let passSigBody = try #require(try PGPPackets.parse(try Armor.decode(request.nodePassphraseSignature)).first(where: { $0.tag == 2 }).map(\.body))
        #expect(try DetachedSig.parse(body: passSigBody).verify(data: Data(passBytes), signerPointMPI: addrPoint) == true)

        // The generated NodeKey unlocks with that passphrase (unlockNode parity)...
        let unlocked = try DecryptChain.unlockSecretKeys(
            armored: request.nodeKey, passphrase: Data(passBytes), idPrefix: "test-new"
        )
        #expect(unlocked.count == 2)
        let nodeCands = unlocked.compactMap(\.candidate)
        #expect(nodeCands.count == 1) // only the #18 subkey is an ECDH candidate
        #expect(unlocked.first(where: { $0.algo == 22 })?.seed == node.generated.edSeed)
        #expect(unlocked.first(where: { $0.algo == 18 })?.seed == node.generated.xScalarLE)

        // ...the Name decrypts with the parent candidate...
        #expect(try MessageDecrypt.decrypt(armored: request.name, candidates: parentCands) == Data("NT-Test".utf8))

        // ...and the NodeHashKey decrypts with the new node candidate to
        // base64-utf8 of a fresh 32-byte key (wire convention, live-verified:
        // the server's own NodeHashKey plaintext is 44B base64), while
        // request.hash is the PARENT-hash HMAC (the server-visible
        // duplicate check).
        let hashBytes = try MessageDecrypt.decrypt(armored: request.nodeHashKey, candidates: nodeCands)
        #expect(hashBytes.count == 44)
        let hashKey32 = try #require(Data(base64Encoded: hashBytes))
        #expect(hashKey32.count == 32)
        #expect(request.hash == NameHash.hex(name: "NT-Test", hashKey: parentHashKey))
        // ...and XAttr roundtrips through the new node candidate.
        #expect(try MessageDecrypt.decrypt(armored: request.xAttr ?? "", candidates: nodeCands) == xAttrJSON)
        // Signer identity variants: set keys encode, nil keys are omitted
        // (Go chokes on explicit nulls for plain strings).
        let encJSON = try JSONEncoder().encode(request)
        let dict = try #require(JSONSerialization.jsonObject(with: encJSON) as? [String: Any])
        #expect(dict["SignatureAddress"] as? String == "test@proton.me")
        #expect(dict["SignatureEmail"] == nil)
    }

    // MARK: - F4.3 file upload

    @Test func fileUploadBlockSplitSizes() throws {
        // Splitting is pure arithmetic: 10 MiB at 4 MiB blocks -> 4+4+2,
        // empty data -> no blocks (the no-blocks commit path).
        let tenMB = Data(repeating: 0x41, count: 10 * 1024 * 1024)
        let chunks = FileUpload.splitBlocks(tenMB)
        #expect(chunks.count == 3)
        #expect(chunks[0].count == 4 * 1024 * 1024)
        #expect(chunks[1].count == 4 * 1024 * 1024)
        #expect(chunks[2].count == 2 * 1024 * 1024)
        #expect(chunks.reduce(Data(), +) == tenMB)
        #expect(FileUpload.splitBlocks(Data()).isEmpty)
        #expect(FileUpload.splitBlocks(Data([1, 2, 3]), blockSize: 2).map(\.count) == [2, 1])
    }

    @Test func fileUploadBlockSizeRule77() throws {
        // Wire Size rule: encrypted packet = plaintext + 51 bytes, exactly
        // (literal "" framing 8 + CFB prefix 18 + MDC 22 + tag-18 framing 3).
        // 26B -> 77B byte-matches the rclone reference; deterministic despite
        // random prefix/session framing.
        let key = Data((0..<32).map { UInt8($0) })
        let plain = Data("12345678901234567890123456".utf8) // 26B
        #expect(plain.count == 26)
        let enc = try FileUpload.encryptBlock(plain, contentKey: key)
        #expect(enc.count == 77)
        #expect(try PGPPackets.parse(enc).map(\.tag) == [18])
        for n in [0, 1, 100] {
            let e = try FileUpload.encryptBlock(Data(repeating: 0x42, count: n), contentKey: key)
            #expect(e.count == n + 51)
        }
        // Large plaintexts use two-octet packet headers (exact +2 here);
        // Size is always the encrypted packet length, whatever it is.
        let big = Data(repeating: 0x42, count: 4096)
        let bigEnc = try FileUpload.encryptBlock(big, contentKey: key)
        #expect(bigEnc.count == 4096 + 53)
        #expect(try FileUpload.decryptBlock(bigEnc, contentKey: key) == big)
        do {
            _ = try FileUpload.encryptBlock(plain, contentKey: Data([1, 2, 3]))
            Issue.record("short content key accepted")
        } catch { /* expected */ }
    }

    @Test func contentKeyPacketSealOpenRoundtrip() throws {
        // Bare PKESK (tag 1 only, unarmored base64, 128 chars for AES-256)
        // seals to the node subkey and opens with the node candidate only.
        let node = try FolderCreate.generateNode()
        let recipient = try #require(node.ecdhRecipient)
        let session = Data((0..<32).map { UInt8(0xFF - $0) })
        let b64 = try FileUpload.sealContentKey(session, nodeRecipient: recipient)
        #expect(b64.count == 128) // reference parity: 96 raw bytes
        #expect(!b64.contains("BEGIN"))
        let raw = try #require(Data(base64Encoded: b64))
        #expect(raw.count == 96)
        #expect(try PGPPackets.parse(raw).map(\.tag) == [1])
        let nodeCands = node.keys.compactMap(\.candidate)
        #expect(nodeCands.count == 1)
        let (cf, opened) = try FileUpload.openContentKey(b64, nodeCandidates: nodeCands)
        #expect(cf == 9)
        #expect(opened == session)
        // PKESK keyID is the node-subkey fingerprint tail (fingerprint input
        // includes the KDF params — reference-verified).
        let pkeskBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 1 }).map(\.body))
        var tail: UInt64 = 0
        for b in node.generated.xFingerprint.suffix(8) { tail = (tail << 8) | UInt64(b) }
        #expect(try PKESK_ECDH.parse(body: pkeskBody).keyID == tail)
        let other = try FolderCreate.generateNode()
        do {
            _ = try FileUpload.openContentKey(b64, nodeCandidates: other.keys.compactMap(\.candidate))
            Issue.record("content key opened with foreign node")
        } catch { /* expected */ }
    }

    @Test func contentKeyPacketSignatureVerifies() throws {
        // Node self-signature over the raw packet bytes: SHA-256 + 16B-salt
        // creation set (hlen 93, like the reference), verifiable with the
        // node Ed point; tampering fails.
        let node = try FolderCreate.generateNode()
        let packet = Data((0..<96).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 1) })
        let armored = try FileUpload.signContentKeyPacket(
            packet, nodeSeedLE: node.generated.edSeed,
            nodeKeyID: Data(node.generated.edFingerprint.suffix(8)),
            nodeFingerprint: node.generated.edFingerprint
        )
        #expect(armored.hasPrefix("-----BEGIN PGP SIGNATURE-----"))
        let body = try #require(try PGPPackets.parse(try Armor.decode(armored)).first(where: { $0.tag == 2 }).map(\.body))
        let hlen = (Int(body[body.startIndex + 4]) << 8) | Int(body[body.startIndex + 5])
        #expect(hlen == 93)
        #expect(body[body.startIndex + 3] == 8) // SHA-256
        let point = try Curve25519.Signing.PrivateKey(rawRepresentation: node.generated.edSeed).publicKey.rawRepresentation
        #expect(try DetachedSig.parse(body: body).verify(data: packet, signerPointMPI: point) == true)
        #expect(try DetachedSig.parse(body: body).verify(data: Data(packet.dropFirst()), signerPointMPI: point) == false)
    }

    @Test func blockEncryptDecryptRoundtrip() throws {
        // Block packets roundtrip through the session key; the block hash is
        // plain SHA-256 (checked against CryptoKit, not ourselves); MDC
        // tampering fails loudly.
        let key = HX("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        let plain = Data("block-plaintext-bytes-0123456789".utf8)
        let enc = try FileUpload.encryptBlock(plain, contentKey: key)
        #expect(try FileUpload.decryptBlock(enc, contentKey: key) == plain)
        // Wire Hash is SHA-256 of the ENCRYPTED bytes (reference-proven:
        // rclone's Hash == sha256(storage bytes)).
        #expect(try FileUpload.blockHash(enc) == Data(SHA256.hash(data: enc)))
        #expect(try FileUpload.blockHash(enc).count == 32)
        var tampered = enc
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        do {
            _ = try FileUpload.decryptBlock(tampered, contentKey: key)
            Issue.record("tampered block accepted")
        } catch { /* expected */ }
    }

    @Test func blockEncSignatureRoundtrip() throws {
        // EncSignature plaintext = the FRAMED 173-byte tag-2 packet (unsigned
        // literal: reference inner is 181B = 2 + 6 + 173), encrypted to the
        // node subkey; the inner signature verifies with the address point
        // over the raw block hash.
        let node = try FolderCreate.generateNode()
        let recipient = try #require(node.ecdhRecipient)
        let addrSeed = Curve25519.Signing.PrivateKey().rawRepresentation
        let addrFP = HX("3333333333333333333333333333333333333333")
        let hash = Data((0..<32).map { UInt8($0 &+ 3) })
        let sigPacket = try FileUpload.blockSignaturePacket(
            blockHash: hash, signerSeedLE: addrSeed,
            signerKeyID: Data(addrFP.suffix(8)), signerFingerprint: addrFP
        )
        #expect(try PGPPackets.parse(sigPacket).map(\.tag) == [2])
        let enc = try FileUpload.encryptSignaturePacket(sigPacket, nodeRecipient: recipient)
        let nodeCands = node.keys.compactMap(\.candidate)
        let back = try MessageDecrypt.decrypt(armored: enc, candidates: nodeCands)
        #expect(Data(back) == sigPacket)
        let sigBody = try #require(try PGPPackets.parse(Data(back)).first(where: { $0.tag == 2 }).map(\.body))
        let addrPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: addrSeed).publicKey.rawRepresentation
        #expect(try DetachedSig.parse(body: sigBody).verify(data: hash, signerPointMPI: addrPoint) == true)
        #expect(try DetachedSig.parse(body: sigBody).verify(data: Data(hash.reversed()), signerPointMPI: addrPoint) == false)
    }

    @Test func manifestSignVerifyRoundtrip() throws {
        // Manifest input = raw-hash concatenation in index order; the
        // address-key signature verifies (incl. the empty-manifest case for
        // 0-byte files).
        let addrSeed = Curve25519.Signing.PrivateKey().rawRepresentation
        let addrFP = HX("4444444444444444444444444444444444444444")
        let addrPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: addrSeed).publicKey.rawRepresentation
        let h1 = Data(repeating: 0x11, count: 32)
        let h2 = Data(repeating: 0x22, count: 32)
        let input = FileUpload.manifestInput(hashes: [h1, h2])
        #expect(input.count == 64)
        #expect(input == h1 + h2)
        let armored = try FileUpload.signManifest(
            input, addressSeedLE: addrSeed,
            addressKeyID: Data(addrFP.suffix(8)), addressFingerprint: addrFP
        )
        let body = try #require(try PGPPackets.parse(try Armor.decode(armored)).first(where: { $0.tag == 2 }).map(\.body))
        #expect(try DetachedSig.parse(body: body).verify(data: input, signerPointMPI: addrPoint) == true)
        let empty = try FileUpload.signManifest(
            FileUpload.manifestInput(hashes: []), addressSeedLE: addrSeed,
            addressKeyID: Data(addrFP.suffix(8)), addressFingerprint: addrFP
        )
        let emptyBody = try #require(try PGPPackets.parse(try Armor.decode(empty)).first(where: { $0.tag == 2 }).map(\.body))
        #expect(try DetachedSig.parse(body: emptyBody).verify(data: Data(), signerPointMPI: addrPoint) == true)
    }

    @Test func xAttrJSONShapeAndRoundtrip() throws {
        // XAttr plaintext carries Common.{ModificationTime,Size,MIMEType,
        // BlockSizes} (capitalized Go-style keys); the commit form is
        // encryptSigned (OPS + literal + SIG) to the node key, node-signed.
        let json = try FileUpload.xAttrJSON(
            modificationTime: Date(timeIntervalSince1970: 1_700_000_000),
            size: 26, mimeType: "text/plain; charset=utf-8", blockSizes: [26]
        )
        let dict = try #require(JSONSerialization.jsonObject(with: json) as? [String: Any])
        let common = try #require(dict["Common"] as? [String: Any])
        #expect(common["Size"] as? Int == 26)
        #expect(common["MIMEType"] as? String == "text/plain; charset=utf-8")
        #expect(common["BlockSizes"] as? [Int] == [26])
        #expect((common["ModificationTime"] as? String)?.contains("2023-11-14") == true)
        let node = try FolderCreate.generateNode()
        let recipient = try #require(node.ecdhRecipient)
        let armored = try FileUpload.buildXAttr(
            json, nodeRecipient: recipient, nodeSeedLE: node.generated.edSeed,
            nodeKeyID: Data(node.generated.edFingerprint.suffix(8)),
            nodeFingerprint: node.generated.edFingerprint
        )
        let nodeCands = node.keys.compactMap(\.candidate)
        #expect(try MessageDecrypt.decrypt(armored: armored, candidates: nodeCands) == json)
        // Inner layout must be OPS + literal + SIG (encryptSigned shape).
        let raw = try Armor.decode(armored)
        let pkeskBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 1 }).map(\.body))
        let (_, sess) = try ECDHDecrypt.decrypt(
            try PKESK_ECDH.parse(body: pkeskBody), privateScalarLE: nodeCands[0].scalarLE,
            curveOIDBody: nodeCands[0].curveOIDBody, fingerprint: nodeCands[0].fingerprint,
            kdfHash: nodeCands[0].kdfHash, kdfCipher: nodeCands[0].kdfCipher
        )
        let sedBody = try #require(try PGPPackets.parse(raw).first(where: { $0.tag == 18 }).map(\.body))
        let inner = try SEDDecrypt.decrypt(sedBody: sedBody, sessionKey: sess, symAlgoID: 9, expectMDC: true)
        #expect(try PGPPackets.parse(inner).map(\.tag) == [4, 11, 2])
        let sigBody = try #require(try PGPPackets.parse(inner).first(where: { $0.tag == 2 }).map(\.body))
        let edPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: node.generated.edSeed).publicKey.rawRepresentation
        #expect(try DetachedSig.parse(body: sigBody).verify(data: json, signerPointMPI: edPoint) == true)
    }

    @Test func fileDraftRequestKeysAndCrypto() throws {
        // Full offline mirror of the reference draft: exactly the 10 wire
        // keys (no NodeHashKey/XAttr/SignatureEmail), every crypto field
        // consumable by parent/node candidates + address/node points.
        let parentX = Curve25519.KeyAgreement.PrivateKey()
        let parentFP = HX("5555555555555555555555555555555555555555")
        let addrSeed = Curve25519.Signing.PrivateKey().rawRepresentation
        let addrFP = HX("6666666666666666666666666666666666666666")
        let addrPoint = try Curve25519.Signing.PrivateKey(rawRepresentation: addrSeed).publicKey.rawRepresentation
        let parentKeys = [KeyringCache.UnlockedKey(
            keyID: "test-parent#18", algo: 18, seed: parentX.rawRepresentation,
            fingerprint: parentFP, kdfHash: 8, kdfCipher: 7, curveOIDBody: NodeKeyGen.ecdhOID
        )]
        let addressKeys = [KeyringCache.UnlockedKey(
            keyID: "test-addr#22", algo: 22, seed: addrSeed,
            fingerprint: addrFP, kdfHash: 8, kdfCipher: 9, curveOIDBody: NodeKeyGen.edOID
        )]
        let parentHashKey = Data((0..<32).map { UInt8($0 &+ 1) })
        let fileData = Data("12345678901234567890123456".utf8) // 26B
        let prepared = try FileUpload.prepareUpload(
            fileName: "NT-F43-FIXTURE.txt", parentLinkID: "parent",
            data: fileData, parentKeys: parentKeys,
            parentHashKey: parentHashKey, addressKeys: addressKeys,
            signatureAddress: "test@proton.me"
        )
        // Wire keys: exactly the reference 10 (encodeIfPresent omissions).
        let encJSON = try JSONEncoder().encode(prepared.request)
        let dict = try #require(JSONSerialization.jsonObject(with: encJSON) as? [String: Any])
        #expect(Set(dict.keys) == [
            "ParentLinkID", "Name", "Hash", "MIMEType", "ContentKeyPacket",
            "ContentKeyPacketSignature", "NodeKey", "NodePassphrase",
            "NodePassphraseSignature", "SignatureAddress",
        ])
        #expect(prepared.request.hash == NameHash.hex(name: "NT-F43-FIXTURE.txt", hashKey: parentHashKey))
        #expect(prepared.mimeType == "text/plain; charset=utf-8")
        #expect(prepared.request.mimeType == "text/plain; charset=utf-8")
        // Content-key packet: unarmored, opens with the node candidate.
        #expect(prepared.request.contentKeyPacket.count == 128)
        let nodeCands = prepared.node.keys.compactMap(\.candidate)
        let (cf, opened) = try FileUpload.openContentKey(
            prepared.request.contentKeyPacket, nodeCandidates: nodeCands
        )
        #expect(cf == 9)
        #expect(opened == prepared.contentKey)
        // ...and its signature verifies with the node point over the SESSION
        // KEY (F8.3-P2 upstream form), not over the raw packet bytes.
        let ckpRaw = try #require(Data(base64Encoded: prepared.request.contentKeyPacket))
        let ckpSigBody = try #require(try PGPPackets.parse(try Armor.decode(prepared.request.contentKeyPacketSignature)).first(where: { $0.tag == 2 }).map(\.body))
        let nodePoint = try Curve25519.Signing.PrivateKey(rawRepresentation: prepared.node.generated.edSeed).publicKey.rawRepresentation
        #expect(try DetachedSig.parse(body: ckpSigBody).verify(data: prepared.contentKey, signerPointMPI: nodePoint) == true)
        #expect(try DetachedSig.parse(body: ckpSigBody).verify(data: ckpRaw, signerPointMPI: nodePoint) == false)
        // Name + passphrase envelope: parent-decryptable, address-signed.
        let parentCands = parentKeys.compactMap(\.candidate)
        #expect(try MessageDecrypt.decrypt(armored: prepared.request.name, candidates: parentCands) == Data("NT-F43-FIXTURE.txt".utf8))
        let passBytes = try MessageDecrypt.decrypt(armored: prepared.request.nodePassphrase, candidates: parentCands)
        #expect(Data(passBytes) == prepared.node.passphrase)
        let passSigBody = try #require(try PGPPackets.parse(try Armor.decode(prepared.request.nodePassphraseSignature)).first(where: { $0.tag == 2 }).map(\.body))
        #expect(try DetachedSig.parse(body: passSigBody).verify(data: Data(passBytes), signerPointMPI: addrPoint) == true)
        // Single-block descriptor: 77B packet (26B + 51 rule, rclone parity),
        // hash over ENCRYPTED bytes, EncSignature (address key over the
        // plaintext) decryptable by the node.
        #expect(prepared.blocks.count == 1)
        let block = prepared.blocks[0]
        #expect(block.index == 1)
        #expect(block.encrypted.count == 77)
        #expect(block.hash == Data(SHA256.hash(data: block.encrypted)))
        #expect(try FileUpload.decryptBlock(block.encrypted, contentKey: prepared.contentKey) == fileData)
        let sigBytes = try MessageDecrypt.decrypt(armored: block.encSignature, candidates: nodeCands)
        let innerSig = try #require(try PGPPackets.parse(Data(sigBytes)).first(where: { $0.tag == 2 }).map(\.body))
        // F8.3-P2 upstream form: the address key signs the PLAINTEXT block.
        #expect(try DetachedSig.parse(body: innerSig).verify(data: fileData, signerPointMPI: addrPoint) == true)
        #expect(try DetachedSig.parse(body: innerSig).verify(data: block.hash, signerPointMPI: addrPoint) == false)
        // Commit: manifest over the block hash verifies with the address
        // point; XAttr decrypts with the node candidate to the JSON.
        let commit = try FileUpload.buildCommit(
            manifestHashes: prepared.blocks.map(\.hash), xAttrJSON: prepared.xAttrJSON,
            node: prepared.node, addressKeys: addressKeys,
            signatureAddress: "test@proton.me"
        )
        let commitJSON = try JSONEncoder().encode(commit)
        let commitDict = try #require(JSONSerialization.jsonObject(with: commitJSON) as? [String: Any])
        #expect(Set(commitDict.keys) == ["ManifestSignature", "SignatureAddress", "XAttr"])
        let manSigBody = try #require(try PGPPackets.parse(try Armor.decode(commit.manifestSignature)).first(where: { $0.tag == 2 }).map(\.body))
        #expect(try DetachedSig.parse(body: manSigBody).verify(
            data: FileUpload.manifestInput(hashes: [block.hash]), signerPointMPI: addrPoint
        ) == true)
        #expect(try MessageDecrypt.decrypt(armored: commit.xAttr, candidates: nodeCands) == prepared.xAttrJSON)
        let xattrDict = try #require(JSONSerialization.jsonObject(with: prepared.xAttrJSON) as? [String: Any])
        let xcommon = try #require(xattrDict["Common"] as? [String: Any])
        #expect(xcommon["Size"] as? Int == 26)
        #expect((xcommon["BlockSizes"] as? [Int]) == [26])
    }

    @Test func mimeTypeSniffVectors() throws {
        #expect(FileUpload.mimeType(fileName: "a.txt", data: Data("hello text".utf8)) == "text/plain; charset=utf-8")
        #expect(FileUpload.mimeType(fileName: "a.html", data: Data("<html>".utf8)) == "text/html; charset=utf-8")
        #expect(FileUpload.mimeType(fileName: "a.json", data: Data("{}".utf8)) == "application/json")
        #expect(FileUpload.mimeType(fileName: "a.bin", data: Data([0x00, 0x01, 0x02])) == "application/octet-stream")
        #expect(FileUpload.mimeType(fileName: "a", data: Data()) == "application/octet-stream")
        #expect(FileUpload.mimeType(fileName: "a.png", data: Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) == "image/png")
        #expect(FileUpload.mimeType(fileName: "a.jpg", data: Data([0xFF, 0xD8, 0xFF, 0x00])) == "image/jpeg")
    }

    @Test func storageMultipartShape() throws {
        // Storage POST body: one "Block"/"blob" octet-stream part; the raw
        // encrypted bytes survive byte-exact (server checks Size against them).
        let bytes = Data((0..<77).map { UInt8($0) })
        let body = FileUpload.multipartBlockBody(boundary: "BND", blockBytes: bytes)
        let text = String(data: body, encoding: .utf8) ?? ""
        #expect(text.hasPrefix("--BND\r\n"))
        #expect(text.contains("Content-Disposition: form-data; name=\"Block\"; filename=\"blob\"\r\n"))
        #expect(text.contains("Content-Type: application/octet-stream\r\n"))
        #expect(text.hasSuffix("\r\n--BND--\r\n"))
        #expect(body.range(of: bytes) != nil)
    }

    @Test func blocksAndCommitJSONKeys() throws {
        // /drive/blocks + checkAvailableHashes wire keys (Go capitalized
        // field names); response fixtures decode with extras ignored.
        let req = RequestBlockUploadsRequest(
            addressID: "addr", shareID: "share", linkID: "link",
            revisionID: "rev",
            blockList: [BlockUploadEntry(index: 1, size: 77, encSignature: "sig", hash: "aGk=")]
        )
        let reqDict = try #require(JSONSerialization.jsonObject(with: try JSONEncoder().encode(req)) as? [String: Any])
        #expect(Set(reqDict.keys) == ["AddressID", "ShareID", "LinkID", "RevisionID", "BlockList"])
        let entry = try #require((reqDict["BlockList"] as? [[String: Any]])?.first)
        #expect(Set(entry.keys) == ["Index", "Size", "EncSignature", "Hash"])
        let hashes = try JSONEncoder().encode(CheckAvailableHashesRequest(hashes: ["ab"]))
        #expect((try #require(JSONSerialization.jsonObject(with: hashes) as? [String: Any]).keys.sorted()) == ["Hashes"])
        let draftResp = """
        {"File":{"ID":"L1","RevisionID":"R1","ClientUID":null},"Code":1000}
        """.data(using: .utf8)!
        #expect(try JSONDecoder().decode(CreateFileResponse.self, from: draftResp).file.revisionID == "R1")
        let blocksResp = """
        {"UploadLinks":[{"BareURL":"https://h/storage/blocks","Token":"T","URL":"https://h/storage/blocks/T","Index":1}],"ThumbnailLink":null,"ThumbnailLinks":[],"Code":1000}
        """.data(using: .utf8)!
        let links = try JSONDecoder().decode(RequestBlockUploadsResponse.self, from: blocksResp).uploadLinks
        #expect(links.count == 1)
        #expect(links[0].bareURL == "https://h/storage/blocks")
        #expect(links[0].index == 1)
        let chkResp = """
        {"AvailableHashes":["ab"],"PendingHashes":[],"Code":1000}
        """.data(using: .utf8)!
        #expect(try JSONDecoder().decode(CheckAvailableHashesResponse.self, from: chkResp).availableHashes == ["ab"])
    }

    @Test func revisionThumbnailAcceptsBoolOrInt() throws {
        // Live-verified: committed files send ActiveRevision.Thumbnail as
        // number (0/1), drafts omit it, some paths send Bool. DriveLink
        // decode must tolerate all shapes (broke getLink/commitRevision/
        // listChildren on committed files).
        func decodeThumbnail(_ fragment: String) throws -> Bool? {
            let json = """
            {"ActiveRevision":{"ID":"R1","Thumbnail":\(fragment)}}
            """.data(using: .utf8)!
            return try JSONDecoder().decode(FileProperties.self, from: json).activeRevision?.thumbnail
        }
        #expect(try decodeThumbnail("0") == false)
        #expect(try decodeThumbnail("1") == true)
        #expect(try decodeThumbnail("false") == false)
        #expect(try decodeThumbnail("true") == true)
        // Missing/null (draft shape) stays nil.
        let missing = try JSONDecoder().decode(
            FileProperties.self,
            from: #"{"ActiveRevision":{"ID":"R1"}}"#.data(using: .utf8)!)
        #expect(missing.activeRevision?.thumbnail == nil)
        // Encode stays Bool.
        let enc = try JSONEncoder().encode(try JSONDecoder().decode(
            RevisionMetadata.self,
            from: #"{"ID":"R1","Thumbnail":1}"#.data(using: .utf8)!))
        let dict = try #require(JSONSerialization.jsonObject(with: enc) as? [String: Any])
        #expect(dict["Thumbnail"] as? Bool == true)
    }
}
