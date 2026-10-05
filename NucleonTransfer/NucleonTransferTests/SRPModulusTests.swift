// Nucleon Transfer — SRP modulus signature + SRP randomness tests (F8.1-S1).
// Real vectors: ProtonMail/go-srp srp_test.go @ d323688777afbb6265d8bc4a51419991a24630ca
// (testModulus / testModulusClearSign / testServerEphemeral and the TestNewAuth
// "test1" signedModulus), all signed by the pinned Proton SRP modulus key.
// Synthetic vectors: clearsigned with a throwaway Ed25519 key via DetachedSign
// and verified through the injected-key path. NO network, NO secrets.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

private let goSRPModulus = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="

private let goSRPModulusClearSign = """
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----
"""

/// go-srp TestNewAuth "test1" signedModulus (a second real Proton modulus).
private let goSRPModulus2ClearSign = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\no4ycZ14/7LfHkuSKWNlpQEh6bwLMVKvo0MFqVq9wHXwkZ/zMcqYaVhqNvLyDB0WY5Uv/Bo23JQsox52lM+4jPydw9/A9saAj8erLCc3ZaZHxOl/a8tlYTq7FeDrbhSSgivwTKJ5Y9otla/U8FATZBxqi7nqDihS5/7x/yK3VRnEsBG1i5DcY1UQK3KD9i9v7N2QTuGFYnRCv0MFsHzrQZWvUa1NsUhozU5PSV5s7hZkb/p6J3B9ybD6+LzuLS9fyLMcVdxzn2WUXG7JLeBbqsoECUfq9KP2waTzVLELOenWUV1wbioceJsaiP97ViwNJdnKx1ICoYu2c+z8ctVcqlw==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAB02wD5AOhMNS/K6/nvaeRhTr5n\niDGMalQccYlb58XzUEhqf3sBAOcTsz0fP3PVdMQYBbqcBl9Y6LGIG9DF4B4H\nZeLCoyYN\n=cAxM\n-----END PGP SIGNATURE-----\n"

private let goSRPServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA=="

private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

/// Throwaway signer for synthetic clearsign fixtures.
private struct TestSigner {
    let seed = Data((0..<32).map { UInt8($0 &* 7 &+ 3) })
    let fingerprint = Data((0..<20).map { UInt8(0xA0 &+ $0) })
    var keyID: Data { Data(fingerprint.suffix(8)) }
    var key: ModulusSigningKey {
        get throws {
            let pub = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
            return ModulusSigningKey(point: pub.rawRepresentation, keyID: keyID,
                                     fingerprint: fingerprint)
        }
    }

    /// Builds a cleartext-signed message. `bodyLines` are emitted verbatim
    /// (already dash-escaped); `signedText` is what gets signed.
    func clearsign(bodyLines: [String], signedText: String, hashHeader: String? = "SHA256",
                   hashAlgo: UInt8 = 8, sigType: UInt8 = 0x01) throws -> String {
        let body = try DetachedSign.signatureBody(
            data: Data(signedText.utf8), signerSeedLE: seed, signerKeyID: keyID,
            signerFingerprint: fingerprint, sigType: sigType, hashAlgo: hashAlgo,
            createdAt: 1_700_000_000
        )
        let armor = Armor.encode(PGPPacketsEncode.packet(tag: 2, body: body), header: "SIGNATURE")
        var lines = ["-----BEGIN PGP SIGNED MESSAGE-----"]
        if let hashHeader { lines.append("Hash: \(hashHeader)") }
        lines.append("")
        lines += bodyLines
        return lines.joined(separator: "\n") + "\n" + armor
    }
}

private func expectBadSignature(_ text: String, key: ModulusSigningKey? = nil) {
    #expect(throws: ProtonAPIError.invalidModulusSignature) {
        _ = try ModulusDecoder.decode(text, key: key)
    }
}

struct SRPModulusTests {
    // MARK: pinned key

    @Test func protonKeyParsesToKnownFingerprint() throws {
        let key = try ModulusSigningKey.proton()
        #expect(hex(key.fingerprint) == "248097092b458509c508dac0350585c4e9518f26")
        #expect(hex(key.keyID) == "350585c4e9518f26")
        #expect(key.point.count == 32)
    }

    // MARK: real Proton vectors (go-srp)

    @Test func realSignedModulusVerifies() throws {
        let n = try ModulusDecoder.decode(goSRPModulusClearSign)
        #expect(n == Data(base64Encoded: goSRPModulus))
        // The verified N also passes the SRP range checks (2048 bits, 3 mod 8).
        let b = BigUInt(dataLE: try #require(Data(base64Encoded: goSRPServerEphemeral)))
        try SRPClient.checkParams(serverEphemeral: b, modulus: BigUInt(dataLE: n))
    }

    @Test func secondRealSignedModulusVerifies() throws {
        let n = try ModulusDecoder.decode(goSRPModulus2ClearSign)
        #expect(n.count == 256)
        #expect(BigUInt(dataLE: n).bitLength == 2048)
    }

    @Test func realSignedModulusVerifiesWithCRLF() throws {
        let crlf = goSRPModulusClearSign.replacingOccurrences(of: "\n", with: "\r\n")
        #expect(try ModulusDecoder.decode(crlf) == Data(base64Encoded: goSRPModulus))
    }

    @Test func tamperedBodyFails() {
        // Flip the first modulus character (W -> X): still valid base64.
        let tampered = goSRPModulusClearSign.replacingOccurrences(
            of: "\n\nW2z5HBi8", with: "\n\nX2z5HBi8")
        #expect(tampered != goSRPModulusClearSign)
        expectBadSignature(tampered)
    }

    @Test func tamperedSignatureFails() {
        // Change one char inside the signature MPI area (go-srp TestReadClearSigned style).
        let tampered = goSRPModulusClearSign.replacingOccurrences(
            of: "GO86yMV4zDZE", with: "GO86yMV4zDZF")
        #expect(tampered != goSRPModulusClearSign)
        expectBadSignature(tampered)
    }

    @Test func bareBase64Rejected() {
        expectBadSignature(goSRPModulus)
    }

    @Test func missingSignatureBlockRejected() {
        let cut = goSRPModulusClearSign.components(separatedBy: "-----BEGIN PGP SIGNATURE-----")[0]
        expectBadSignature(cut)
    }

    @Test func dataAfterSignatureRejected() {
        expectBadSignature(goSRPModulusClearSign + "data after modulus")
    }

    @Test func realMessageWithWrongPinnedKeyRejected() throws {
        expectBadSignature(goSRPModulusClearSign, key: try TestSigner().key)
    }

    // MARK: synthetic vectors (injected key)

    @Test func syntheticCanonicalTextVerifies() throws {
        let s = TestSigner()
        // Trailing whitespace is stripped and "- " escapes removed before hashing;
        // canonical text uses CRLF with no trailing line break.
        let msg = try s.clearsign(bodyLines: ["QUJD  ", "- REVG\t"], signedText: "QUJD\r\nREVG")
        #expect(try ModulusDecoder.decode(msg, key: try s.key) == Data("ABCDEF".utf8))
        // Same message against the pinned Proton key: wrong signer.
        expectBadSignature(msg)
    }

    @Test func syntheticWrongSignerRejected() throws {
        let s = TestSigner()
        let msg = try s.clearsign(bodyLines: ["QUJD"], signedText: "QUJD")
        let other = ModulusSigningKey(
            point: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
            keyID: s.keyID, fingerprint: s.fingerprint) // same issuer, wrong point
        expectBadSignature(msg, key: other)
    }

    @Test func syntheticUnsupportedHashRejected() throws {
        let s = TestSigner()
        let sha1 = try s.clearsign(bodyLines: ["QUJD"], signedText: "QUJD",
                                   hashHeader: "SHA1", hashAlgo: 2)
        expectBadSignature(sha1, key: try s.key)
        // No Hash header means MD5 per RFC 4880 §7.
        let noHeader = try s.clearsign(bodyLines: ["QUJD"], signedText: "QUJD", hashHeader: nil)
        expectBadSignature(noHeader, key: try s.key)
        // Header and signature packet disagree.
        let mismatch = try s.clearsign(bodyLines: ["QUJD"], signedText: "QUJD",
                                       hashHeader: "SHA512", hashAlgo: 8)
        expectBadSignature(mismatch, key: try s.key)
    }

    @Test func syntheticBinarySignatureTypeRejected() throws {
        let s = TestSigner()
        let msg = try s.clearsign(bodyLines: ["QUJD"], signedText: "QUJD", sigType: 0x00)
        expectBadSignature(msg, key: try s.key)
    }

    @Test func syntheticUnescapedDashLineRejected() throws {
        let s = TestSigner()
        let msg = try s.clearsign(bodyLines: ["-QUJD"], signedText: "-QUJD")
        expectBadSignature(msg, key: try s.key)
    }

    // MARK: SRP randomness

    private func realInputs() throws -> (n: Data, b: Data) {
        (try ModulusDecoder.decode(goSRPModulusClearSign),
         try #require(Data(base64Encoded: goSRPServerEphemeral)))
    }

    @Test func secretRetryExhaustionThrows() throws {
        let (n, b) = try realInputs()
        var draws = 0
        #expect(throws: ProtonAPIError.srpParamsOutOfBounds("could not draw client secret in range")) {
            _ = try SRPClient.generateProofs(
                hashedPassword: Data(repeating: 1, count: 256), serverEphemeral: b, modulus: n,
                randomBytes: { count in
                    draws += 1
                    return Data(repeating: 0xFF, count: count) // always >= N-1
                })
        }
        #expect(draws == SRPClient.maxSecretDraws)
    }

    @Test func randomFailurePropagates() throws {
        let (n, b) = try realInputs()
        #expect(throws: ProtonAPIError.secureRandomFailed) {
            _ = try SRPClient.generateProofs(
                hashedPassword: Data(repeating: 1, count: 256), serverEphemeral: b, modulus: n,
                randomBytes: { _ in throw ProtonAPIError.secureRandomFailed })
        }
    }

    @Test func outOfRangeInjectedSecretThrows() throws {
        let (n, b) = try realInputs()
        #expect(throws: ProtonAPIError.srpParamsOutOfBounds("client secret out of range")) {
            _ = try SRPClient.generateProofs(
                hashedPassword: Data(repeating: 1, count: 256), serverEphemeral: b, modulus: n,
                clientSecret: Data([0x05]))
        }
    }

    /// End-to-end with the real RNG (feasible in debug since F8.3-P5's
    /// Montgomery modPow): plays the server side of SRP-6a on the real
    /// modulus and checks both proofs agree. Server: v = g^x, B = k*v + g^b,
    /// S = (A * v^u)^b; client derives the same S = (B - k*g^x)^(a + u*x).
    @Test func generateProofsWithRealRandomMatchesServer() throws {
        let (nData, _) = try realInputs()
        let n = BigUInt(dataLE: nData)
        let byteLength = SRPClient.byteLength
        let hashedPassword = try SecureRandom.bytes(byteLength)
        let x = BigUInt(dataLE: hashedPassword)
        let k = try SRPClient.multiplier(modulus: n)
        let v = BigUInt.modPow(.two, x, n)
        let serverSecret = BigUInt(dataLE: try SecureRandom.bytes(byteLength))
        let bigB = BigUInt.mod(BigUInt.add(BigUInt.modMul(k, v, n),
                                           BigUInt.modPow(.two, serverSecret, n)), n)
        let bData = bigB.toDataLE(length: byteLength)

        let proofs = try SRPClient.generateProofs(
            hashedPassword: hashedPassword, serverEphemeral: bData, modulus: nData)

        let aData = proofs.clientEphemeral
        let a = BigUInt(dataLE: aData)
        #expect(a.compare(.one) > 0 && a.compare(n) < 0)
        let u = BigUInt(dataLE: ExpandHash.expand(aData + bData).prefix(byteLength))
        let shared = BigUInt.modPow(BigUInt.modMul(a, BigUInt.modPow(v, u, n), n), serverSecret, n)
        let sData = shared.toDataLE(length: byteLength)
        let clientProof = ExpandHash.expand(aData + bData + sData)
        #expect(proofs.clientProof == clientProof)
        #expect(proofs.expectedServerProof == ExpandHash.expand(aData + clientProof + sData))
    }

    @Test func secureRandomReturnsFreshBytes() throws {
        let a = try SecureRandom.bytes(32), c = try SecureRandom.bytes(32)
        #expect(a.count == 32 && c.count == 32 && a != c)
        #expect(try SecureRandom.bytes(0).isEmpty)
    }

    // MARK: auth version

    @Test(arguments: [0, 1, 2, 5])
    func legacyOrUnknownAuthVersionRejected(version: Int) {
        #expect(throws: ProtonAPIError.unsupportedAuthVersion(version)) {
            _ = try PasswordHash.hash(version: version, password: Data("pw".utf8), username: "u",
                                      salt: Data(count: 10), modulus: Data(count: 256),
                                      bcrypt: UnimplementedBcryptHasher())
        }
    }

    @Test func newErrorsHaveActionableMessages() {
        #expect(UserFacingError.message(for: ProtonAPIError.unsupportedAuthVersion(2))
            .contains("auth version 2"))
        #expect(UserFacingError.message(for: ProtonAPIError.invalidModulusSignature)
            .contains("signature verification"))
        #expect(!UserFacingError.message(for: ProtonAPIError.secureRandomFailed).isEmpty)
    }
}
