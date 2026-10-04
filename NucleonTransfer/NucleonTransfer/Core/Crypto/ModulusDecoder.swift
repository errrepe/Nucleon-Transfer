// Nucleon Transfer — SRP modulus decoding + clearsign verification (F8.1-S1).
// The server sends the modulus as a PGP cleartext-signed base64 string. Like
// go-srp readClearSignedMessage, we verify the signature against Proton's
// pinned SRP modulus key BEFORE using N: a TLS MITM must not be able to
// substitute a weak modulus and run an offline attack on the password.
// Fail-closed: a bare base64 modulus (no envelope) is rejected.
import Foundation

/// Pinned EdDSA public key that signs SRP moduli.
struct ModulusSigningKey: Sendable, Equatable {
    /// 32-byte Ed25519 public point (0x40 native prefix stripped).
    var point: Data
    /// 8-byte v4 key ID (fingerprint tail).
    var keyID: Data
    /// 20-byte v4 fingerprint.
    var fingerprint: Data

    /// Parses an armored v4 EdDSA (algo 22, curve Ed25519) public key block;
    /// only the primary key packet (tag 6) is used.
    static func parse(armored: String) throws -> ModulusSigningKey {
        let packets = try PGPPackets.parse(try Armor.decode(armored))
        guard let primary = packets.first, primary.tag == 6 else {
            throw ProtonAPIError.invalidModulusSignature
        }
        let body = primary.body
        // v4 public key: version(1) created(4) algo(1) oidLen(1) oid point-MPI
        guard body.count > 7, body[body.startIndex] == 4,
              body[body.startIndex + 5] == 22 else {
            throw ProtonAPIError.invalidModulusSignature
        }
        let oidLen = Int(body[body.startIndex + 6])
        let oidStart = body.startIndex + 7
        guard oidStart + oidLen <= body.endIndex,
              Data(body[oidStart..<(oidStart + oidLen)]) == NodeKeyGen.edOID else {
            throw ProtonAPIError.invalidModulusSignature
        }
        let (mpi, end) = try MPI.read(body, from: 7 + oidLen)
        guard end == body.count, mpi.count == 33, mpi.first == 0x40 else {
            throw ProtonAPIError.invalidModulusSignature
        }
        let fp = try PGPFingerprint.v4(publicBody: body)
        return ModulusSigningKey(point: Data(mpi.dropFirst()), keyID: Data(fp.suffix(8)),
                                 fingerprint: fp)
    }

    /// Proton's SRP modulus signing key ("proton@srp.modulus"), copied verbatim
    /// from ProtonMail/go-srp srp.go `modulusPubkey`, commit
    /// d323688777afbb6265d8bc4a51419991a24630ca. Fingerprint
    /// 248097092B458509C508DAC0350585C4E9518F26.
    static let protonArmored = """
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
    L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
    BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
    MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
    Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
    kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
    hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
    WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
    =Y4Mw
    -----END PGP PUBLIC KEY BLOCK-----
    """

    static func proton() throws -> ModulusSigningKey {
        try parse(armored: protonArmored)
    }
}

enum ModulusDecoder {
    /// Hash algorithms accepted for the clearsign digest (RFC 4880 §9.4 IDs):
    /// SHA-256/384/512/224. MD5 and SHA-1 are refused.
    private static let allowedHashes: [String: UInt8] = [
        "SHA256": 8, "SHA384": 9, "SHA512": 10, "SHA224": 11,
    ]

    /// Verifies the clearsigned modulus with `key` (Proton's pinned key by
    /// default; injectable for tests) and returns the decoded modulus bytes.
    /// Every failure throws `ProtonAPIError.invalidModulusSignature`.
    static func decode(_ string: String, key: ModulusSigningKey? = nil) throws -> Data {
        let signer = try key ?? ModulusSigningKey.proton()
        do {
            return try verifyAndDecode(string, signer: signer)
        } catch let e as ProtonAPIError where e == .invalidModulusSignature {
            throw e
        } catch {
            // Armor/packet/signature parse errors: same fail-closed verdict.
            throw ProtonAPIError.invalidModulusSignature
        }
    }

    private static func verifyAndDecode(_ string: String, signer: ModulusSigningKey) throws -> Data {
        let bad = ProtonAPIError.invalidModulusSignature
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let lines = trimmed.components(separatedBy: "\n").map {
            $0.hasSuffix("\r") ? String($0.dropLast()) : $0
        }
        // Envelope: BEGIN line first, END SIGNATURE line last (go-srp rejects
        // any data after the signed message).
        guard lines.first == "-----BEGIN PGP SIGNED MESSAGE-----",
              lines.last == "-----END PGP SIGNATURE-----",
              let sigIdx = lines.firstIndex(of: "-----BEGIN PGP SIGNATURE-----"),
              let emptyIdx = lines.firstIndex(where: { $0.isEmpty }),
              emptyIdx < sigIdx else {
            throw bad
        }

        // Armor headers (RFC 4880 §7): "Hash: A, B". Other headers ignored.
        var headerHashes: Set<UInt8> = []
        var sawHashHeader = false
        for header in lines[1..<emptyIdx] {
            guard let colon = header.firstIndex(of: ":") else { throw bad }
            let name = header[..<colon].trimmingCharacters(in: .whitespaces)
            guard name == "Hash" else { continue }
            sawHashHeader = true
            for raw in header[header.index(after: colon)...].split(separator: ",") {
                let algo = raw.trimmingCharacters(in: .whitespaces).uppercased()
                guard let id = allowedHashes[algo] else { throw bad }
                headerHashes.insert(id)
            }
        }
        // No Hash header means MD5 (RFC 4880 §7) — refused.
        guard sawHashHeader else { throw bad }

        // Cleartext → canonical text (RFC 4880 §7.1): dash-unescape, strip
        // trailing spaces/tabs, CRLF line endings, no trailing line break.
        var bodyLines: [String] = []
        for line in lines[(emptyIdx + 1)..<sigIdx] {
            var l = line
            if l.hasPrefix("- ") {
                l = String(l.dropFirst(2))
            } else if l.hasPrefix("-") {
                throw bad // unescaped dash line is malformed
            }
            while let last = l.last, last == " " || last == "\t" { l.removeLast() }
            bodyLines.append(l)
        }
        let canonical = Data(bodyLines.joined(separator: "\r\n").utf8)

        // Exactly one v4 EdDSA text-signature packet.
        let sigArmor = lines[sigIdx...].joined(separator: "\n")
        let packets = try PGPPackets.parse(try Armor.decode(sigArmor))
        guard packets.count == 1, packets[0].tag == 2 else { throw bad }
        let sig = try DetachedSig.parse(body: packets[0].body)
        guard sig.type == 0x01, // canonical text document
              headerHashes.contains(sig.hashAlgo) else {
            throw bad
        }
        if let issuer = issuerKeyID(sigBody: packets[0].body), issuer != signer.keyID {
            throw bad // signed by another key
        }
        guard try sig.verify(data: canonical, signerPointMPI: signer.point) else {
            throw bad
        }

        guard let modulus = Data(base64Encoded: bodyLines.joined()), !modulus.isEmpty else {
            throw bad
        }
        return modulus
    }

    /// Issuer key ID (subpacket 16) or issuer-fingerprint tail (33) from a v4
    /// signature body's hashed/unhashed areas; nil when absent.
    private static func issuerKeyID(sigBody body: Data) -> Data? {
        var o = 4
        var found: Data? = nil
        for _ in 0..<2 {
            guard o + 2 <= body.count else { return nil }
            let len = (Int(body[body.startIndex + o]) << 8) | Int(body[body.startIndex + o + 1])
            o += 2
            guard o + len <= body.count else { return nil }
            let area = Data(body[(body.startIndex + o)..<(body.startIndex + o + len)])
            o += len
            var i = 0
            while i < area.count {
                let l0 = Int(area[i])
                var spLen: Int
                if l0 < 192 {
                    spLen = l0; i += 1
                } else if l0 < 255 {
                    guard i + 1 < area.count else { return nil }
                    spLen = ((l0 - 192) << 8) + Int(area[i + 1]) + 192; i += 2
                } else {
                    guard i + 4 < area.count else { return nil }
                    spLen = (Int(area[i + 1]) << 24) | (Int(area[i + 2]) << 16)
                        | (Int(area[i + 3]) << 8) | Int(area[i + 4])
                    i += 5
                }
                guard spLen >= 1, i + spLen <= area.count else { return nil }
                let type = area[i] & 0x7F
                let value = area[(i + 1)..<(i + spLen)]
                if type == 16, value.count == 8 {
                    found = Data(value)
                } else if type == 33, value.count == 21 {
                    found = Data(value.suffix(8))
                }
                i += spLen
            }
        }
        return found
    }
}
