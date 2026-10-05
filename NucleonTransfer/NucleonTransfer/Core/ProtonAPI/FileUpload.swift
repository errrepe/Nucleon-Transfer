// Nucleon Transfer — single-file upload (F4.3).
// Pure crypto + request builders; network lives in DriveClient (one method
// per stage so the live battery can probe draft/blocks/commit incrementally).
//
// REFERENCE (decoded from the rclone capture /tmp/rclone-fileup.log +
// /tmp/f43ref/*.json of a 26-byte text file; packet layouts verified by
// decoding every armored blob — see analysis below):
//
// Flow: POST .../links/{parent}/checkAvailableHashes {Hashes:[nameHashHex]}
// (x2, identical — client quirk) -> POST .../shares/{id}/files (10 keys)
// -> POST /drive/blocks {AddressID, ShareID, LinkID, RevisionID, BlockList}
// -> resp {UploadLinks:[{BareURL, Token, URL, Index}]} ->
// POST {BareURL}/storage/blocks (multipart, Pm-Storage-Token header) ->
// PUT .../files/{linkID}/revisions/{revID} {ManifestSignature,
// SignatureAddress, XAttr} -> Code 1000. Draft resp: {File:{ID, RevisionID}}.
//
// Semantics found:
// - Draft `Hash` = NameHash HMAC-SHA256 hex (same as folders — the remote
//   object's sha1 in the log differs, so this is NOT a content hash).
// - checkAvailableHashes = duplicate-name probe under the parent (server
//   echoes the hash in AvailableHashes, PendingHashes empty).
// - `ContentKeyPacket` (128-char unarmored base64 = 96 raw bytes) = a BARE
//   PKESK tag-1 packet: the 32-byte content session key ECDH-wrapped to the
//   file node's own #18 subkey (PKESK keyID == node-subkey fingerprint tail;
//   note the fingerprint input INCLUDES the KDF params). No SED, no armor.
// - `ContentKeyPacketSignature` = detached signature by the NODE primary
//   (#22, issuer == node keyID) over the 32-byte SESSION KEY (F8.3-P2,
//   upstream form: go-proton-api link_file_types.go
//   `SetContentKeyPacketAndSignature` — `kr.SignDetached(
//   NewPlainMessage(newSessionKey.Key))`, verified by link_types.go
//   `GetSessionKey`). F4.3 builds signed the raw 96 PKESK bytes; downloads
//   still accept that legacy form (FileDownload.verifyContentKey).
// - Block `Hash` (44-char base64 = 32 bytes — NOT 28-char SHA-1) = SHA-256
//   of the PLAINTEXT block (VARIANT-UNCERTAIN: encrypted-bytes input would
//   also be 32 bytes; plaintext chosen because the server never sees keys).
// - Block `Size` = full ENCRYPTED SED packet length: plaintext 26B -> 77B
//   (literal "" framing 8B + 18B CFB prefix + 22B MDC + tag-18 framing 3B).
// - Block `EncSignature` (719-char armor = 321 raw: PKESK 96 + SED packet
//   225) = UNSIGNED literal encryption to the node subkey of the FRAMED
//   173-byte tag-2 detached-signature packet, made by the ADDRESS key over
//   the PLAINTEXT block (F8.3-P2, upstream form: Proton-API-Bridge
//   file_upload.go `DefaultAddrKR.SignDetachedEncrypted(dataPlainMessage,
//   newNodeKR)`; ProtonDriveApps/sdk C# ContentEncryptionOperations.cs
//   `EncryptContentBlockAsync` — detached signature of the plaintext
//   stream by the signing key, `PgpEncrypter.Encrypt(signature, fileKey)`).
//   F4.3 builds signed the encrypted-block hash; downloads still accept it
//   (FileDownload.verifyBlockSignature).
// - `ManifestSignature` (detached armor, body 171B) = ADDRESS-key signature
//   (issuer == NodePassphraseSignature issuer) over the manifest, defined as
//   the concatenation of the RAW 32-byte block hashes in index order
//   (VARIANT-UNCERTAIN: base64-ASCII concatenation is the alternative).
// - `XAttr` at commit (719-char armor = 484 raw: PKESK 96 + SED packet 388)
//   = encryptSigned JSON (~148 bytes for the fixture) to the node subkey,
//   inline-signed by the NODE key (mirrors the folder NodeHashKey precedent;
//   VARIANT-UNCERTAIN: exact JSON schema + signer; our Common schema is a
//   best-effort superset Proton clients parse tolerantly). Since F8.3-P6
//   Common also carries `Digests: {"SHA1": "<lowercase hex>"}`, the SHA-1 of
//   the whole PLAINTEXT, like upstream (see FileXAttrDigests).
// - `MIMEType` = Go http.DetectContentType style ("text/plain; charset=utf-8"
//   for text); the storage host comes from UploadLinks BareURL at runtime.
// - Wild node keys use KDF 03 01 0a 09 (SHA-512/AES-256); ours use
//   03 01 08 07 (live-verified for folders in F4.2) — both are valid RFC 6637.
import CryptoKit
import Foundation

enum FileUploadError: Error, Sendable {
    case noParentECDHKey
    case noAddressSigningKey
    case noNodeECDHKey
    case noNodeSigningKey
    case badHashKeyLength
    case badContentKeyLength
    case badContentKeyPacket
    case uploadLinkMismatch
    case emptyUploadLinks
}

enum FileUpload {
    /// Default block size (TRANSFERS.md: versioned BlockFormatVersion, 4 MiB).
    /// Exposed as a parameter everywhere so the live battery can try small
    /// blocks; the single-block path is the verified-first target.
    static let defaultBlockSize = 4 * 1024 * 1024
    /// Content session-key cipher (AES-256). Stored in the PKESK cipherFunc
    /// byte, so download clients pick it up dynamically.
    static let sessionCipher: UInt8 = 9
    static let sessionKeyLength = 32

    // MARK: - staged material

    /// One encrypted block of the whole-file path (prepareUpload; tests and
    /// benchmarks — the app streams EncodedBlocks instead).
    struct BlockDescriptor: Sendable {
        /// 1-based block index (wire `Index`).
        var index: Int
        /// Plaintext chunk (kept for XAttr BlockSizes + manifest input).
        var plaintext: Data
        /// Raw 32-byte SHA-256 of the plaintext (wire `Hash` is its base64).
        var hash: Data
        /// Raw encrypted SED tag-18 packet (storage body; wire `Size`).
        var encrypted: Data
        /// Armored EncSignature message (detached block-hash sig, encrypted).
        var encSignature: String
    }

    /// Everything prepareUpload derives (pure, offline-testable).
    struct PreparedUpload: Sendable {
        var request: CreateFileRequest
        var node: FolderCreate.NodeMaterial
        var contentKey: Data
        var blocks: [BlockDescriptor]
        /// Canonical XAttr JSON (plaintext; encrypted at commit time).
        var xAttrJSON: Data
        var mimeType: String
    }

    // MARK: - pure pieces

    /// Splits data into plaintext chunks (last chunk may be short).
    static func splitBlocks(_ data: Data, blockSize: Int = defaultBlockSize) -> [Data] {
        guard !data.isEmpty else { return [] }
        let size = max(1, blockSize)
        var out: [Data] = []
        var off = data.startIndex
        while off < data.endIndex {
            let end = data.index(off, offsetBy: size, limitedBy: data.endIndex) ?? data.endIndex
            out.append(Data(data[off..<end]))
            off = end
        }
        return out
    }

    /// Raw 32-byte SHA-256 of an ENCRYPTED block (wire `Hash` = its base64).
    /// Reference-verified: Hash == sha256(storage bytes), not plaintext.
    static func blockHash(_ encrypted: Data) throws -> Data {
        try PGPHash.digest(id: 8, encrypted)
    }

    /// Encrypts one plaintext block with the content session key: literal
    /// (empty filename, like the reference) inside SEIPDv1, returned as the
    /// RAW tag-18 packet (the storage body; its count is the wire `Size`).
    static func encryptBlock(_ plaintext: Data, contentKey: Data) throws -> Data {
        guard contentKey.count == sessionKeyLength else { throw FileUploadError.badContentKeyLength }
        // Literal header + data streamed through the cipher unjoined, framed
        // in one buffer (F8.3-P1): no plaintext/packet copies.
        let literalHeader = LiteralPacket.header(dataCount: plaintext.count, filename: "")
        return try SEDEncrypt.seipdPacket(
            innerParts: [literalHeader, plaintext], sessionKey: contentKey, symAlgoID: sessionCipher
        )
    }

    /// Decrypts a raw encrypted block packet with the content session key
    /// (inverse of encryptBlock; used by tests and the F4.4 download path).
    static func decryptBlock(_ packet: Data, contentKey: Data) throws -> Data {
        guard contentKey.count == sessionKeyLength else { throw FileUploadError.badContentKeyLength }
        let packets = try PGPPackets.parseSlices(packet) // body decrypted in place, no copy
        guard let sedBody = packets.first(where: { $0.tag == 18 }).map(\.body) else {
            throw FileUploadError.badContentKeyPacket
        }
        let inner = try SEDDecrypt.decrypt(
            sedBody: sedBody, sessionKey: contentKey,
            symAlgoID: sessionCipher, expectMDC: true
        )
        return try SEDDecrypt.literalData(inner)
    }

    /// Seals a 32-byte content session key to the node subkey: returns the
    /// UNARMORED base64 of the bare PKESK tag-1 packet (128 chars for
    /// AES-256 — reference parity).
    static func sealContentKey(_ sessionKey: Data, nodeRecipient: EncryptRecipient) throws -> String {
        guard sessionKey.count == sessionKeyLength else { throw FileUploadError.badContentKeyLength }
        let pkeskBody = try ECDHEncrypt.encrypt(
            sessionKey: sessionKey, cipherFunc: sessionCipher,
            recipientPublicPoint: nodeRecipient.publicPoint,
            recipientFingerprint: nodeRecipient.fingerprint,
            curveOIDBody: nodeRecipient.curveOIDBody,
            kdfHash: nodeRecipient.kdfHash, kdfCipher: nodeRecipient.kdfCipher
        )
        return PGPPacketsEncode.packet(tag: 1, body: pkeskBody).base64EncodedString()
    }

    /// Opens a ContentKeyPacket with the node candidates (inverse of seal).
    static func openContentKey(
        _ packetB64: String, nodeCandidates: [DecryptCandidate]
    ) throws -> (cipherFunc: UInt8, sessionKey: Data) {
        guard let raw = Data(base64Encoded: packetB64) else {
            throw FileUploadError.badContentKeyPacket
        }
        let packets = try PGPPackets.parse(raw)
        guard packets.count == 1, packets[0].tag == 1 else {
            throw FileUploadError.badContentKeyPacket
        }
        let pkesk = try PKESK_ECDH.parse(body: packets[0].body)
        var lastError: Error = FileUploadError.badContentKeyPacket
        for c in nodeCandidates {
            do {
                return try ECDHDecrypt.decrypt(
                    pkesk, privateScalarLE: c.scalarLE,
                    curveOIDBody: c.curveOIDBody, fingerprint: c.fingerprint,
                    kdfHash: c.kdfHash, kdfCipher: c.kdfCipher
                )
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    /// Upstream ContentKeyPacketSignature: detached node self-signature
    /// over the 32-byte content SESSION KEY (go-proton-api
    /// `SetContentKeyPacketAndSignature`). Armored detached output.
    static func signSessionKey(
        _ sessionKey: Data, nodeSeedLE: Data, nodeKeyID: Data, nodeFingerprint: Data
    ) throws -> String {
        guard sessionKey.count == sessionKeyLength else { throw FileUploadError.badContentKeyLength }
        return try DetachedSign.sign(
            data: sessionKey, signerSeedLE: nodeSeedLE, signerKeyID: nodeKeyID,
            signerFingerprint: nodeFingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
    }

    /// LEGACY (F4.3 builds): detached node self-signature over the RAW
    /// content-key-packet bytes. Uploads no longer produce it; kept so
    /// tests can build the legacy variant downloads still accept.
    static func signContentKeyPacket(
        _ packetRaw: Data, nodeSeedLE: Data, nodeKeyID: Data, nodeFingerprint: Data
    ) throws -> String {
        try DetachedSign.sign(
            data: packetRaw, signerSeedLE: nodeSeedLE, signerKeyID: nodeKeyID,
            signerFingerprint: nodeFingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
    }

    /// Upstream block signature: framed detached-signature packet over the
    /// PLAINTEXT block by the address key (later encrypted into
    /// EncSignature — gopenpgp `SignDetachedEncrypted`).
    static func blockSignaturePacket(
        plaintext: Data, signerSeedLE: Data, signerKeyID: Data, signerFingerprint: Data
    ) throws -> Data {
        try signaturePacket(
            over: plaintext, signerSeedLE: signerSeedLE,
            signerKeyID: signerKeyID, signerFingerprint: signerFingerprint
        )
    }

    /// LEGACY (F4.3 builds): signature packet over the raw 32-byte
    /// ENCRYPTED-block hash. Uploads no longer produce it; downloads still
    /// accept it for files those builds uploaded.
    static func blockSignaturePacket(
        blockHash: Data, signerSeedLE: Data, signerKeyID: Data, signerFingerprint: Data
    ) throws -> Data {
        try signaturePacket(
            over: blockHash, signerSeedLE: signerSeedLE,
            signerKeyID: signerKeyID, signerFingerprint: signerFingerprint
        )
    }

    private static func signaturePacket(
        over data: Data, signerSeedLE: Data, signerKeyID: Data, signerFingerprint: Data
    ) throws -> Data {
        let body = try DetachedSign.signatureBody(
            data: data, signerSeedLE: signerSeedLE, signerKeyID: signerKeyID,
            signerFingerprint: signerFingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
        return PGPPacketsEncode.packet(tag: 2, body: body)
    }

    /// Encrypts a framed block-signature packet to the node subkey (unsigned
    /// literal — reference inner size 181B proves no inline OPS/SIG).
    static func encryptSignaturePacket(
        _ sigPacket: Data, nodeRecipient: EncryptRecipient
    ) throws -> String {
        try MessageEncrypt.encrypt(
            plaintext: sigPacket, recipient: nodeRecipient,
            cipher: sessionCipher, useMDC: true
        )
    }

    /// Manifest input: concatenation of the raw block hashes in index order
    /// (VARIANT-UNCERTAIN: base64-ASCII concatenation is the alternative).
    static func manifestInput(hashes: [Data]) -> Data {
        hashes.reduce(Data(), +)
    }

    /// Detached manifest signature by the address key (armored, for commit).
    static func signManifest(
        _ input: Data, addressSeedLE: Data, addressKeyID: Data, addressFingerprint: Data
    ) throws -> String {
        try DetachedSign.sign(
            data: input, signerSeedLE: addressSeedLE, signerKeyID: addressKeyID,
            signerFingerprint: addressFingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
    }

    /// Canonical XAttr JSON (plaintext). Go clients marshal capitalized
    /// field names; ModificationTime is RFC3339 UTC, Size/BlockSizes are
    /// PLAINTEXT sizes, `sha1` is the raw 20-byte SHA-1 of the whole
    /// plaintext (written as Digests.SHA1, lowercase hex).
    /// VARIANT-UNCERTAIN: exact schema (extra fields).
    static func xAttrJSON(
        modificationTime: Date, size: Int64, mimeType: String, blockSizes: [Int], sha1: Data
    ) throws -> Data {
        // RFC3339 UTC with second precision (Go time.RFC3339 shape). New
        // formatter per call: ISO8601DateFormatter is not Sendable (Swift 6).
        let stamp: String = {
            let f = ISO8601DateFormatter()
            f.formatOptions = [.withInternetDateTime]
            f.timeZone = TimeZone(identifier: "UTC")
            return f.string(from: modificationTime)
        }()
        let xattr = FileXAttr(common: FileXAttrCommon(
            modificationTime: stamp, size: size, mimeType: mimeType,
            blockSizes: blockSizes, digests: FileXAttrDigests(sha1: sha1)
        ))
        // Sorted keys: JSONEncoder's key order is otherwise unspecified, and
        // the doc comment promises a canonical form (F8.3-P2).
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(xattr)
    }

    /// Encrypts + node-signs the XAttr JSON for the commit stage (mirrors the
    /// folder NodeHashKey precedent: the node attests its own metadata).
    static func buildXAttr(
        _ json: Data, nodeRecipient: EncryptRecipient,
        nodeSeedLE: Data, nodeKeyID: Data, nodeFingerprint: Data
    ) throws -> String {
        try MessageEncrypt.encryptSigned(
            plaintext: json, recipient: nodeRecipient,
            signerSeedLE: nodeSeedLE, signerKeyID: nodeKeyID,
            signerFingerprint: nodeFingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
    }

    /// MIME sniff in the spirit of Go http.DetectContentType (which produced
    /// the reference "text/plain; charset=utf-8"): magic bytes first, then
    /// text-vs-binary, defaulting to application/octet-stream. Extension
    /// hints cover types sniffing cannot see (e.g. short UTF-8 docs still
    /// sniff as text, which is what we want).
    static func mimeType(fileName: String, data: Data) -> String {
        let head = data.prefix(512)
        // Magic signatures (subset of Go's sniff table that matters here).
        if head.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] as [UInt8]) { return "image/png" }
        if head.count >= 3, head[head.startIndex] == 0xFF, head[head.index(head.startIndex, offsetBy: 1)] == 0xD8,
           head[head.index(head.startIndex, offsetBy: 2)] == 0xFF { return "image/jpeg" }
        if head.starts(with: Data("GIF87a".utf8)) || head.starts(with: Data("GIF89a".utf8)) { return "image/gif" }
        if head.starts(with: Data("%PDF-".utf8)) { return "application/pdf" }
        if head.starts(with: Data([0x50, 0x4B, 0x03, 0x04])) {
            let ext = URL(fileURLWithPath: fileName).pathExtension.lowercased()
            if ext == "docx" { return "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }
            if ext == "xlsx" { return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }
            return "application/zip"
        }
        if head.isEmpty { return "application/octet-stream" }
        // Binary (NUL/control) vs text, like Go's DetectContentType.
        let bytes = Array(head)
        let binary = bytes.contains { b in
            b == 0 || (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D && b != 0x1B)
        }
        if binary { return "application/octet-stream" }
        let ext = URL(fileURLWithPath: fileName).pathExtension.lowercased()
        switch ext {
        case "html", "htm": return "text/html; charset=utf-8"
        case "css": return "text/css; charset=utf-8"
        case "csv": return "text/csv; charset=utf-8"
        case "xml": return "text/xml; charset=utf-8"
        case "json": return "application/json"
        case "js", "mjs": return "text/javascript; charset=utf-8"
        default: return "text/plain; charset=utf-8"
        }
    }

    /// Builds a multipart/form-data body for one storage-block POST (part
    /// name "Block", filename "blob", application/octet-stream — log parity).
    static func multipartBlockBody(boundary: String, blockBytes: Data) -> Data {
        var out = Data()
        out.append(Data("--\(boundary)\r\n".utf8))
        out.append(Data("Content-Disposition: form-data; name=\"Block\"; filename=\"blob\"\r\n".utf8))
        out.append(Data("Content-Type: application/octet-stream\r\n".utf8))
        out.append(Data("\r\n".utf8))
        out.append(blockBytes)
        out.append(Data("\r\n--\(boundary)--\r\n".utf8))
        return out
    }

    static func freshBoundary() -> String {
        Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
            .map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - draft assembly (pure)

    /// Address-key signer of block signatures + the manifest.
    struct Signer: Sendable {
        var seed: Data
        var keyID: Data
        var fingerprint: Data

        /// The first #22 address key (folder/name parity).
        init(addressKeys: [KeyringCache.UnlockedKey]) throws {
            guard let key = addressKeys.first(where: { $0.algo == 22 }) else {
                throw FileUploadError.noAddressSigningKey
            }
            seed = key.seed
            keyID = Data(key.fingerprint.suffix(8))
            fingerprint = key.fingerprint
        }
    }

    /// Draft material computed ONCE per upload (F8.3-P2): the create-file
    /// request (name, node key, passphrase, sealed + signed content key)
    /// and the secrets the block pipeline needs. No file bytes.
    struct PreparedDraft: Sendable {
        var request: CreateFileRequest
        var node: FolderCreate.NodeMaterial
        var contentKey: Data
        var mimeType: String
        /// Node subkey: block EncSignatures are encrypted to it.
        var nodeRecipient: EncryptRecipient
        var signer: Signer
    }

    /// One encoded block: what /drive/blocks + storage + manifest need.
    /// The plaintext is NOT kept (only its size, for XAttr BlockSizes).
    struct EncodedBlock: Sendable {
        /// 1-based block index (wire `Index`).
        var index: Int
        var plaintextSize: Int
        /// Raw 32-byte SHA-256 of the ENCRYPTED packet (wire `Hash`).
        var hash: Data
        /// Raw encrypted SED tag-18 packet (storage body; wire `Size`).
        var encrypted: Data
        /// Armored EncSignature (address signature over the plaintext,
        /// encrypted to the node key).
        var encSignature: String

        var uploadEntry: BlockUploadEntry {
            BlockUploadEntry(
                index: index, size: encrypted.count,
                encSignature: encSignature, hash: hash.base64EncodedString()
            )
        }
    }

    /// Builds the draft material: fresh node keypair (reuse via `node`),
    /// fresh content session key (override via `contentKey`), encrypted name
    /// + passphrase to the PARENT keyring inline/detached-signed by the
    /// address key (folder parity), content-key packet sealed to the node
    /// and node-signed over the session key (upstream form).
    static func prepareDraft(
        fileName: String,
        parentLinkID: String,
        mimeType: String,
        parentKeys: [KeyringCache.UnlockedKey],
        parentHashKey: Data,
        addressKeys: [KeyringCache.UnlockedKey],
        signatureAddress: String? = nil,
        signatureEmail: String? = nil,
        node: FolderCreate.NodeMaterial? = nil,
        contentKey: Data? = nil
    ) throws -> PreparedDraft {
        guard parentHashKey.count == 32 else { throw FileUploadError.badHashKeyLength }
        guard let parentECDH = parentKeys.first(where: { $0.algo == 18 }),
              let parentRecipient = EncryptRecipient(
                  privateScalarLE: parentECDH.seed, fingerprint: parentECDH.fingerprint,
                  curveOIDBody: parentECDH.curveOIDBody,
                  kdfHash: parentECDH.kdfHash, kdfCipher: parentECDH.kdfCipher
              )
        else {
            throw FileUploadError.noParentECDHKey
        }
        let signer = try Signer(addressKeys: addressKeys)
        let material = try node ?? FolderCreate.generateNode()
        guard let nodeRecipient = material.ecdhRecipient else {
            throw FileUploadError.noNodeECDHKey
        }
        let nodeKeyID = Data(material.generated.edFingerprint.suffix(8))
        let nfcName = fileName.precomposedStringWithCanonicalMapping

        let key: Data
        if let contentKey {
            guard contentKey.count == sessionKeyLength else { throw FileUploadError.badContentKeyLength }
            key = contentKey
        } else {
            key = Data((0..<sessionKeyLength).map { _ in UInt8.random(in: .min ... .max) })
        }

        // Name + passphrase envelope: identical to folders (parent recipient,
        // address signer, SHA-256 + fresh 16B salts).
        let encName = try MessageEncrypt.encryptSigned(
            plaintext: Data(nfcName.utf8), recipient: parentRecipient,
            signerSeedLE: signer.seed, signerKeyID: signer.keyID,
            signerFingerprint: signer.fingerprint, hashAlgo: 8,
            salt: DetachedSign.freshSalt(16)
        )
        let encPassphrase = try MessageEncrypt.encrypt(
            plaintext: material.passphrase, recipient: parentRecipient
        )
        let passSig = try DetachedSign.sign(
            data: material.passphrase, signerSeedLE: signer.seed,
            signerKeyID: signer.keyID, signerFingerprint: signer.fingerprint,
            hashAlgo: 8, salt: DetachedSign.freshSalt(16)
        )

        // Content-key packet: bare PKESK to the node subkey; the node signs
        // the SESSION KEY (upstream), not the packet bytes.
        let ckpB64 = try sealContentKey(key, nodeRecipient: nodeRecipient)
        let ckpSig = try signSessionKey(
            key, nodeSeedLE: material.generated.edSeed, nodeKeyID: nodeKeyID,
            nodeFingerprint: material.generated.edFingerprint
        )
        let request = CreateFileRequest(
            parentLinkID: parentLinkID,
            name: encName,
            hash: NameHash.hex(name: nfcName, hashKey: parentHashKey),
            mimeType: mimeType,
            contentKeyPacket: ckpB64,
            contentKeyPacketSignature: ckpSig,
            nodeKey: material.generated.armoredKey,
            nodePassphrase: encPassphrase,
            nodePassphraseSignature: passSig,
            signatureAddress: signatureAddress,
            signatureEmail: signatureEmail
        )
        return PreparedDraft(
            request: request, node: material, contentKey: key, mimeType: mimeType,
            nodeRecipient: nodeRecipient, signer: signer
        )
    }

    /// One block through the upload crypto: encrypt (literal "" in
    /// SEIPDv1) -> SHA-256 of the CIPHERTEXT (wire Hash, reference-proven)
    /// -> address signature over the PLAINTEXT -> encrypted to the node.
    /// Pure and nonisolated: the streaming pipeline runs it off any actor.
    static func encodeBlock(index: Int, plaintext: Data, draft: PreparedDraft) throws -> EncodedBlock {
        let encrypted = try encryptBlock(plaintext, contentKey: draft.contentKey)
        let hash = try blockHash(encrypted)
        let sigPacket = try blockSignaturePacket(
            plaintext: plaintext, signerSeedLE: draft.signer.seed,
            signerKeyID: draft.signer.keyID, signerFingerprint: draft.signer.fingerprint
        )
        let encSig = try encryptSignaturePacket(sigPacket, nodeRecipient: draft.nodeRecipient)
        return EncodedBlock(
            index: index, plaintextSize: plaintext.count, hash: hash,
            encrypted: encrypted, encSignature: encSig
        )
    }

    /// Whole-file convenience (tests, benchmarks): prepareDraft + every
    /// block encoded up front. The app streams instead (StreamingUpload).
    static func prepareUpload(
        fileName: String,
        parentLinkID: String,
        data: Data,
        mimeType: String? = nil,
        modificationTime: Date = Date(),
        blockSize: Int = defaultBlockSize,
        parentKeys: [KeyringCache.UnlockedKey],
        parentHashKey: Data,
        addressKeys: [KeyringCache.UnlockedKey],
        signatureAddress: String? = nil,
        signatureEmail: String? = nil,
        node: FolderCreate.NodeMaterial? = nil,
        contentKey: Data? = nil
    ) throws -> PreparedUpload {
        let mime = mimeType ?? self.mimeType(fileName: fileName, data: data)
        let draft = try prepareDraft(
            fileName: fileName, parentLinkID: parentLinkID, mimeType: mime,
            parentKeys: parentKeys, parentHashKey: parentHashKey,
            addressKeys: addressKeys, signatureAddress: signatureAddress,
            signatureEmail: signatureEmail, node: node, contentKey: contentKey
        )
        var blocks: [BlockDescriptor] = []
        for (i, chunk) in splitBlocks(data, blockSize: blockSize).enumerated() {
            let encoded = try encodeBlock(index: i + 1, plaintext: chunk, draft: draft)
            blocks.append(BlockDescriptor(
                index: encoded.index, plaintext: chunk, hash: encoded.hash,
                encrypted: encoded.encrypted, encSignature: encoded.encSignature
            ))
        }
        let xattr = try xAttrJSON(
            modificationTime: modificationTime, size: Int64(data.count),
            mimeType: mime, blockSizes: blocks.map(\.plaintext.count),
            sha1: Data(Insecure.SHA1.hash(data: data))
        )
        return PreparedUpload(
            request: draft.request, node: draft.node, contentKey: draft.contentKey,
            blocks: blocks, xAttrJSON: xattr, mimeType: mime
        )
    }

    /// Builds the revision-commit request: manifest signature (address key
    /// over the concatenated raw block hashes) + node-encrypted XAttr.
    static func buildCommit(
        manifestHashes: [Data],
        xAttrJSON: Data,
        node: FolderCreate.NodeMaterial,
        addressKeys: [KeyringCache.UnlockedKey],
        signatureAddress: String? = nil,
        signatureEmail: String? = nil
    ) throws -> CommitRevisionRequest {
        guard let signer = addressKeys.first(where: { $0.algo == 22 }) else {
            throw FileUploadError.noAddressSigningKey
        }
        guard let nodeRecipient = node.ecdhRecipient else {
            throw FileUploadError.noNodeECDHKey
        }
        let nodeKeyID = Data(node.generated.edFingerprint.suffix(8))
        let manifestSig = try signManifest(
            manifestInput(hashes: manifestHashes),
            addressSeedLE: signer.seed,
            addressKeyID: Data(signer.fingerprint.suffix(8)),
            addressFingerprint: signer.fingerprint
        )
        let xattr = try buildXAttr(
            xAttrJSON, nodeRecipient: nodeRecipient,
            nodeSeedLE: node.generated.edSeed, nodeKeyID: nodeKeyID,
            nodeFingerprint: node.generated.edFingerprint
        )
        return CommitRevisionRequest(
            manifestSignature: manifestSig,
            signatureAddress: signatureAddress,
            signatureEmail: signatureEmail,
            xAttr: xattr
        )
    }
}

// MARK: - XAttr model

/// Extended-attributes JSON stored (node-encrypted) on the file revision.
/// Go clients marshal capitalized field names; keep them for interop.
struct FileXAttr: Codable, Sendable {
    var common: FileXAttrCommon
    enum CodingKeys: String, CodingKey { case common = "Common" }
}

struct FileXAttrCommon: Codable, Sendable {
    var modificationTime: String
    var size: Int64
    var mimeType: String
    var blockSizes: [Int]
    /// Optional on decode: F4.3-F8.3-P5 builds (and other clients) omit it.
    var digests: FileXAttrDigests?
    enum CodingKeys: String, CodingKey {
        case modificationTime = "ModificationTime"
        case size = "Size"
        case mimeType = "MIMEType"
        case blockSizes = "BlockSizes"
        case digests = "Digests"
    }
}

/// `Common.Digests`: content digests of the whole PLAINTEXT file (F8.3-P6).
/// Upstream shape, every client the same: key "SHA1", LOWERCASE HEX of the
/// 20-byte SHA-1 over the plaintext stream in block order.
/// - henrybear327/go-proton-api link_file_types.go `RevisionXAttrCommon`
///   (`Digests map[string]string`), filled by Proton-API-Bridge
///   file_upload.go `uploadFile` — `Digests: map[string]string{"SHA1":
///   digests}` with `hex.EncodeToString(sha1Digests.Sum(nil))`, the hasher
///   fed every plaintext block in `uploadAndCollectBlockData`;
/// - ProtonDriveApps/sdk js internal/upload/digests.ts `UploadDigests`
///   (`bytesToHex(sha1)`), internal/nodes/extendedAttributes.ts
///   (`Common.Digests = { SHA1: ... }`);
/// - ProtonDriveApps/sdk C# Api/Files/FileContentDigestsDto.cs
///   (`[JsonPropertyName("SHA1")]`, `ForgivingBytesToHexJsonConverter`),
///   hashed while streaming in Nodes/Upload/RevisionWriter.cs.
struct FileXAttrDigests: Codable, Sendable, Equatable {
    /// Lowercase hex (40 chars).
    var sha1: String
    enum CodingKeys: String, CodingKey { case sha1 = "SHA1" }

    init(sha1Hex: String) { self.sha1 = sha1Hex }

    init(sha1 raw: Data) {
        self.sha1 = raw.map { String(format: "%02x", $0) }.joined()
    }
}
