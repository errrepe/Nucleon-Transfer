// Nucleon Transfer — armored message encrypt (F4.1).
// Mirror of MessageDecrypt: [PKESK v3 ECDH (tag 1)] + [SED (tag 9) |
// SEIPDv1 (tag 18 v1)], literal (tag 11) payload, armored output via
// Armor.encode.
import CryptoKit
import Foundation

enum MessageEncryptError: Error, Sendable {
    case badSessionKey
}

/// ECDH recipient for encryption (public half). Fingerprint + KDF ids +
/// curve OID mirror DecryptCandidate; the public point replaces the private
/// scalar (encryption needs no secrets).
struct EncryptRecipient: Sendable {
    var publicPoint: Data // X25519 point, 32 bytes (0x40 prefix tolerated)
    var fingerprint: Data // recipient v4 fingerprint (20 bytes)
    var curveOIDBody: Data
    var kdfHash: UInt8
    var kdfCipher: UInt8

    /// Builds a recipient from a private scalar by deriving the X25519
    /// public point. Used for self-roundtrips and parent-keyring name
    /// encryption. Returns nil for malformed scalars.
    init?(
        privateScalarLE: Data,
        fingerprint: Data,
        curveOIDBody: Data,
        kdfHash: UInt8,
        kdfCipher: UInt8
    ) {
        guard privateScalarLE.count == 32,
              let priv = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateScalarLE) else {
            return nil
        }
        self.publicPoint = priv.publicKey.rawRepresentation
        self.fingerprint = fingerprint
        self.curveOIDBody = curveOIDBody
        self.kdfHash = kdfHash
        self.kdfCipher = kdfCipher
    }

    init(
        publicPoint: Data,
        fingerprint: Data,
        curveOIDBody: Data,
        kdfHash: UInt8,
        kdfCipher: UInt8
    ) {
        self.publicPoint = publicPoint
        self.fingerprint = fingerprint
        self.curveOIDBody = curveOIDBody
        self.kdfHash = kdfHash
        self.kdfCipher = kdfCipher
    }
}

/// New-format packet framing (RFC 4880 §4): header + definite length.
enum PGPPacketsEncode {
    static func packet(tag: Int, body: Data) -> Data {
        var out = header(tag: tag, length: body.count)
        out.reserveCapacity(out.count + body.count)
        out.append(body)
        return out
    }

    /// Tag octet + definite length for a body of `length` bytes (lets large
    /// bodies be written straight after it without a framing copy).
    static func header(tag: Int, length n: Int) -> Data {
        var out = Data([UInt8(0xC0 | (tag & 0x3F))])
        if n < 192 {
            out.append(UInt8(n))
        } else if n < 8384 {
            let v = n - 192
            out.append(UInt8((v >> 8) + 192))
            out.append(UInt8(v & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((n >> 24) & 0xFF))
            out.append(UInt8((n >> 16) & 0xFF))
            out.append(UInt8((n >> 8) & 0xFF))
            out.append(UInt8(n & 0xFF))
        }
        return out
    }
}

/// Literal packet builder (tag 11): format 'b' + filename + zero date + data.
enum LiteralPacket {
    /// Literal Data packet body (tag 11 framing included). Official packets
    /// carry a real modification date — zeros are a needless divergence, so
    /// default to now (override for deterministic vectors).
    static func build(data: Data, filename: String = "", date: UInt32 = UInt32(Date().timeIntervalSince1970)) -> Data {
        var out = header(dataCount: data.count, filename: filename, date: date)
        out.reserveCapacity(out.count + data.count)
        out.append(data)
        return out
    }

    /// Everything `build` emits before the data: tag 11 framing + format,
    /// filename and date. `header + data == build(data)` (F8.3-P1: the
    /// block encrypt streams header and data without concatenating them).
    static func header(dataCount: Int, filename: String = "", date: UInt32 = UInt32(Date().timeIntervalSince1970)) -> Data {
        let nameBytes = Array(filename.utf8.prefix(255))
        var fields = Data([0x62, UInt8(nameBytes.count)])
        fields.append(contentsOf: nameBytes)
        fields.append(UInt8((date >> 24) & 0xFF))
        fields.append(UInt8((date >> 16) & 0xFF))
        fields.append(UInt8((date >> 8) & 0xFF))
        fields.append(UInt8(date & 0xFF))
        return PGPPacketsEncode.header(tag: 11, length: fields.count + dataCount) + fields
    }
}

enum MessageEncrypt {
    /// Encrypts plaintext to one ECDH recipient, returning an armored
    /// message. Mirror of MessageDecrypt.decrypt.
    /// - `cipher`: session symmetric algo (7/8/9, default 9 = AES-256).
    /// - `useMDC`: true = SEIPDv1 tag 18 (default), false = SED tag 9.
    /// - `sessionKey`: override for deterministic vectors; random when nil.
    static func encrypt(
        plaintext: Data,
        recipient: EncryptRecipient,
        cipher: UInt8 = 9,
        useMDC: Bool = true,
        filename: String = "",
        sessionKey: Data? = nil
    ) throws -> String {
        let literal = LiteralPacket.build(data: plaintext, filename: filename)
        return try seal(
            inner: literal, recipient: recipient,
            cipher: cipher, useMDC: useMDC, sessionKey: sessionKey
        )
    }

    /// Shared PKESK + SED framing + armor for a pre-built inner packet stream.
    static func seal(
        inner: Data,
        recipient: EncryptRecipient,
        cipher: UInt8 = 9,
        useMDC: Bool = true,
        sessionKey: Data? = nil
    ) throws -> String {
        let keyLen = try PGPSymmetricAlgo.keyLength(id: cipher)
        let session: Data
        if let s = sessionKey {
            guard s.count == keyLen else { throw MessageEncryptError.badSessionKey }
            session = s
        } else {
            session = Data((0..<keyLen).map { _ in UInt8.random(in: .min ... .max) })
        }
        let sedBody = try SEDEncrypt.encrypt(
            inner: inner, sessionKey: session, symAlgoID: cipher, useMDC: useMDC
        )
        let pkeskBody = try ECDHEncrypt.encrypt(
            sessionKey: session, cipherFunc: cipher,
            recipientPublicPoint: recipient.publicPoint,
            recipientFingerprint: recipient.fingerprint,
            curveOIDBody: recipient.curveOIDBody,
            kdfHash: recipient.kdfHash, kdfCipher: recipient.kdfCipher
        )
        var raw = PGPPacketsEncode.packet(tag: 1, body: pkeskBody)
        raw.append(PGPPacketsEncode.packet(tag: useMDC ? 18 : 9, body: sedBody))
        return Armor.encode(raw)
    }

    /// Encrypts plaintext to one ECDH recipient with an inline one-pass
    /// Ed25519 signature (OPS tag 4 + literal tag 11 + SIG tag 2 inside the
    /// SED). Mirrors gopenpgp KeyRing.Encrypt(plain, signingKR) as used by
    /// Proton clients for link names (`SetName`) and node hash keys
    /// (`SetNodeHashKey`): encryption to the recipient keyring, signature by
    /// the address/node key. Our MessageDecrypt skips tags 4/2 and extracts
    /// the literal, so signed messages stay readable by DecryptChain.
    /// - `signerSeedLE`: 32-byte Ed25519 seed of the signer.
    /// - `signerKeyID`: 8-byte issuer key ID (signer fingerprint tail).
    /// - `signerFingerprint`: full 20-byte fingerprint (notation-set sigs).
    static func encryptSigned(
        plaintext: Data,
        recipient: EncryptRecipient,
        signerSeedLE: Data,
        signerKeyID: Data,
        signerFingerprint: Data,
        hashAlgo: UInt8 = 10,
        cipher: UInt8 = 9,
        useMDC: Bool = true,
        filename: String = "",
        sessionKey: Data? = nil,
        salt: Data? = nil
    ) throws -> String {
        var inner = try DetachedSign.onePassPacket(hashAlgo: hashAlgo, signerKeyID: signerKeyID)
        inner.append(LiteralPacket.build(data: plaintext, filename: filename))
        let sigBody = try DetachedSign.signatureBody(
            data: plaintext, signerSeedLE: signerSeedLE,
            signerKeyID: signerKeyID, signerFingerprint: signerFingerprint,
            hashAlgo: hashAlgo, salt: salt
        )
        inner.append(PGPPacketsEncode.packet(tag: 2, body: sigBody))
        return try seal(
            inner: inner, recipient: recipient,
            cipher: cipher, useMDC: useMDC, sessionKey: sessionKey
        )
    }

    /// Encrypts a link name to the PARENT keyring's recipient (names are
    /// encrypted to the parent key: the root's name to the share key, a
    /// child's name to the parent node key). Mirror of
    /// DecryptChain.decryptName (which decrypts with parent candidates).
    static func encryptName(
        _ name: String,
        parentRecipient: EncryptRecipient,
        cipher: UInt8 = 9,
        useMDC: Bool = true
    ) throws -> String {
        try encrypt(
            plaintext: Data(name.utf8), recipient: parentRecipient,
            cipher: cipher, useMDC: useMDC
        )
    }
}
