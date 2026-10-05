// Nucleon Transfer — Ed25519 signing for folder creation (F4.2).
// v4 signatures (type 0x00 binary-doc, 0x13 certification, 0x18 subkey
// binding), hash = Hash(data || trailer) where trailer = body[0..<hashedEnd]
// + [0x04, 0xFF] + len32BE(hashedEnd) (go-crypto sign.go parity). Emitted
// tail is two MPIs (R, S) — the GnuPG-canonical form our parser and
// go-crypto both accept.
//
// Hashed sets mirror Proton clients byte-for-byte (live-captured from an
// rclone-made folder + official vault keys):
//   - binary/cert/binding: creation-time CRITICAL (0x82), issuer keyID,
//     salt notation (0x14: flags=0, "salt@notations.openpgpjs.org", fresh
//     salt — the OpenPGP.js anti-replay randomization the server requires),
//     issuer fingerprint (0x21).
//   - certification (0x13) also carries the gopenpgp preference set:
//     pref-sym [09 07], pref-hash [08], pref-compress [00 02],
//     primary-uid [01], key-flags CRITICAL [03], features [01].
//   - binding (0x18) carries key-flags CRITICAL [0C] instead of prefs.
// Hash is SHA-256 (8) and salts are 16 bytes in creation contexts (rclone
// parity); the generic default stays SHA-512/32B for other uses.
// Inline form (one-pass tag 4 + literal tag 11 + sig tag 2) mirrors
// gopenpgp KeyRing.Encrypt(plain, signingKR); our MessageDecrypt skips tags
// 4/2 and extracts the literal, so signed messages stay readable.
import CryptoKit
import Foundation

/// OpenPGP.js salt notation name (anti-replay: fresh random value per sig).
let saltNotationName = "salt@notations.openpgpjs.org"

/// UID Proton clients stamp on generated node keys (rclone-captured).
let nodeKeyUID = "Drive key <noreply@protonmail.com>"

enum DetachedSignError: Error, Sendable {
    case badSeed
    case badKeyID
}

enum DetachedSign {
    /// Fresh random salt for notation subpackets (16B in creation contexts).
    static func freshSalt(_ count: Int = 32) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }

    /// Builds a v4 signature body (tag 2 content, unframed) over `data`.
    /// - `signerSeedLE`: 32-byte Ed25519 seed.
    /// - `signerKeyID`: 8-byte issuer key ID (v4 fingerprint tail).
    /// - `signerFingerprint`: full 20-byte v4 fingerprint (issuer-fp subpacket).
    /// - `sigType`: 0x00 binary-doc (default); use certificationBody /
    ///   subkeyBindingBody for key packets.
    /// - `salt`: notation salt (fresh 32B random when nil).
    static func signatureBody(
        data: Data,
        signerSeedLE: Data,
        signerKeyID: Data,
        signerFingerprint: Data,
        sigType: UInt8 = 0x00,
        hashAlgo: UInt8 = 10,
        createdAt: UInt32 = UInt32(Date().timeIntervalSince1970),
        salt: Data? = nil
    ) throws -> Data {
        guard signerKeyID.count == 8, signerFingerprint.count == 20 else {
            throw DetachedSignError.badSeed
        }
        let hashed = creationSubpacket(createdAt: createdAt)
            + issuerSubpacket(keyID: signerKeyID)
            + notationSubpacket(salt: salt ?? freshSalt())
            + issuerFpSubpacket(fingerprint: signerFingerprint)
        return try core(
            data: data, sigType: sigType, hashed: hashed,
            hashAlgo: hashAlgo, seed: signerSeedLE
        )
    }

    /// Self-certification (type 0x13) over a primary key + UID, with the
    /// gopenpgp preference set. Data framing per RFC 4880 §5.2.4.
    static func certificationBody(
        primaryPub: Data,
        uid: Data,
        signerSeedLE: Data,
        signerKeyID: Data,
        signerFingerprint: Data,
        hashAlgo: UInt8 = 8,
        createdAt: UInt32 = UInt32(Date().timeIntervalSince1970),
        salt: Data? = nil
    ) throws -> Data {
        guard signerKeyID.count == 8, signerFingerprint.count == 20 else {
            throw DetachedSignError.badSeed
        }
        let hashed = creationSubpacket(createdAt: createdAt)
            + sp(0x0B, critical: false, Data([0x09, 0x07]))
            + issuerSubpacket(keyID: signerKeyID)
            + notationSubpacket(salt: salt ?? freshSalt())
            + sp(0x15, critical: false, Data([0x08]))
            + sp(0x16, critical: false, Data([0x00, 0x02]))
            + sp(0x19, critical: false, Data([0x01]))
            + sp(0x1B, critical: true, Data([0x03]))
            + sp(0x1E, critical: false, Data([0x01]))
            + issuerFpSubpacket(fingerprint: signerFingerprint)
        return try core(
            data: framedPub(primaryPub) + framedUID(uid), sigType: 0x13,
            hashed: hashed, hashAlgo: hashAlgo, seed: signerSeedLE
        )
    }

    /// Subkey binding signature (type 0x18) over primary + subkey publics.
    static func subkeyBindingBody(
        primaryPub: Data,
        subkeyPub: Data,
        signerSeedLE: Data,
        signerKeyID: Data,
        signerFingerprint: Data,
        hashAlgo: UInt8 = 8,
        createdAt: UInt32 = UInt32(Date().timeIntervalSince1970),
        salt: Data? = nil
    ) throws -> Data {
        guard signerKeyID.count == 8, signerFingerprint.count == 20 else {
            throw DetachedSignError.badSeed
        }
        let hashed = creationSubpacket(createdAt: createdAt)
            + issuerSubpacket(keyID: signerKeyID)
            + notationSubpacket(salt: salt ?? freshSalt())
            + sp(0x1B, critical: true, Data([0x0C]))
            + issuerFpSubpacket(fingerprint: signerFingerprint)
        return try core(
            data: framedPub(primaryPub) + framedPub(subkeyPub), sigType: 0x18,
            hashed: hashed, hashAlgo: hashAlgo, seed: signerSeedLE
        )
    }

    /// Armored detached signature ("PGP SIGNATURE" header).
    static func sign(
        data: Data,
        signerSeedLE: Data,
        signerKeyID: Data,
        signerFingerprint: Data,
        hashAlgo: UInt8 = 10,
        createdAt: UInt32 = UInt32(Date().timeIntervalSince1970),
        salt: Data? = nil
    ) throws -> String {
        let body = try signatureBody(
            data: data, signerSeedLE: signerSeedLE, signerKeyID: signerKeyID,
            signerFingerprint: signerFingerprint, hashAlgo: hashAlgo,
            createdAt: createdAt, salt: salt
        )
        return Armor.encode(PGPPacketsEncode.packet(tag: 2, body: body), header: "SIGNATURE")
    }

    /// Framed one-pass signature packet (tag 4, v3) referencing the same
    /// signer, for embedding ahead of the literal packet.
    /// nested=0x01: live-captured official packets end in 0x01 even though
    /// the next packet is the literal (RFC 4880 §5.4 would say 0x00) — the
    /// OpenPGP.js quirk Proton clients emit, and the server evidently
    /// expects byte-parity here. Do NOT "fix" to 0x00 (tried 2026-09-30).
    static func onePassPacket(hashAlgo: UInt8, signerKeyID: Data) throws -> Data {
        guard signerKeyID.count == 8 else { throw DetachedSignError.badKeyID }
        var body = Data([0x03, 0x00, hashAlgo, 22])
        body.append(signerKeyID)
        body.append(0x01) // nested=1: Proton parity (literal + SIG follow)
        return PGPPacketsEncode.packet(tag: 4, body: body)
    }

    /// MPI encoding: 2-octet bit length + minimal big-endian content
    /// (mirrors ECDHEncrypt.mpiEncode).
    static func mpiEncode(_ content: Data) -> Data {
        let bytes = Array(content)
        var i = 0
        while i < bytes.count, bytes[i] == 0 { i += 1 }
        let bitlen: Int
        if i == bytes.count {
            bitlen = 0
        } else {
            var b = bytes[i]
            var n = 0
            while b != 0 { n += 1; b >>= 1 }
            bitlen = (bytes.count - i - 1) * 8 + n
        }
        let stripped = bytes[i...]
        return Data([UInt8((bitlen >> 8) & 0xFF), UInt8(bitlen & 0xFF)]) + stripped
    }

    // MARK: - private

    /// Shared v4 signing core: body + trailer + hash + R/S MPIs.
    private static func core(
        data: Data, sigType: UInt8, hashed: Data, hashAlgo: UInt8, seed: Data
    ) throws -> Data {
        guard seed.count == 32,
              let priv = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
            throw DetachedSignError.badSeed
        }
        var body = Data([0x04, sigType, 22, hashAlgo])
        body.append(UInt8((hashed.count >> 8) & 0xFF))
        body.append(UInt8(hashed.count & 0xFF))
        body.append(hashed)
        body.append(contentsOf: [0x00, 0x00]) // no unhashed subpackets
        let hashedEnd = 4 + 2 + hashed.count
        var trailer = Data(body[body.startIndex..<(body.startIndex + hashedEnd)])
        trailer.append(0x04)
        trailer.append(0xFF)
        let l = UInt32(hashedEnd)
        trailer.append(UInt8((l >> 24) & 0xFF))
        trailer.append(UInt8((l >> 16) & 0xFF))
        trailer.append(UInt8((l >> 8) & 0xFF))
        trailer.append(UInt8(l & 0xFF))
        let digest = try PGPHash.digest(id: hashAlgo, parts: [data, trailer])
        let sig = try priv.signature(for: digest)
        body.append(digest[digest.startIndex])
        body.append(digest[digest.index(after: digest.startIndex)])
        body.append(mpiEncode(Data(sig.prefix(32))))
        body.append(mpiEncode(Data(sig.suffix(32))))
        return body
    }

    /// Subpacket: len(1) + type(|critical) + body. All lengths < 192 here.
    private static func sp(_ type: UInt8, critical: Bool, _ body: Data) -> Data {
        var out = Data([UInt8(1 + body.count), type | (critical ? 0x80 : 0)])
        out.append(body)
        return out
    }

    private static func creationSubpacket(createdAt: UInt32) -> Data {
        var time = Data()
        time.append(UInt8((createdAt >> 24) & 0xFF))
        time.append(UInt8((createdAt >> 16) & 0xFF))
        time.append(UInt8((createdAt >> 8) & 0xFF))
        time.append(UInt8(createdAt & 0xFF))
        return sp(0x02, critical: true, time)
    }

    private static func issuerSubpacket(keyID: Data) -> Data {
        sp(0x10, critical: false, keyID)
    }

    private static func notationSubpacket(salt: Data) -> Data {
        let name = Data(saltNotationName.utf8)
        var body = Data([0x00, 0x00, 0x00, 0x00])
        body.append(UInt8((name.count >> 8) & 0xFF))
        body.append(UInt8(name.count & 0xFF))
        body.append(UInt8((salt.count >> 8) & 0xFF))
        body.append(UInt8(salt.count & 0xFF))
        body.append(name)
        body.append(salt)
        return sp(0x14, critical: false, body)
    }

    private static func issuerFpSubpacket(fingerprint: Data) -> Data {
        sp(0x21, critical: false, Data([0x04]) + fingerprint)
    }

    /// RFC 4880 §5.2.4 certification framing: 0x99 + len16 + packet body.
    static func framedPub(_ pub: Data) -> Data {
        Data([0x99, UInt8((pub.count >> 8) & 0xFF), UInt8(pub.count & 0xFF)]) + pub
    }

    /// UID framing: 0xB4 + len32 + user ID.
    static func framedUID(_ uid: Data) -> Data {
        var out = Data([0xB4])
        let l = UInt32(uid.count)
        out.append(UInt8((l >> 24) & 0xFF))
        out.append(UInt8((l >> 16) & 0xFF))
        out.append(UInt8((l >> 8) & 0xFF))
        out.append(UInt8(l & 0xFF))
        out.append(uid)
        return out
    }
}
