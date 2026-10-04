// Nucleon Transfer — file download core (F5).
// Offline-testable: pure reassembly + hash verify + destination planning.
// Live wiring (DriveClient revisions/storage + key unlock) lives in
// DriveDownloadAdapter.swift; UI progress lives in the browser view-model.
//
// REFERENCE (rclone --dump bodies /tmp/f5ref/rclone-download.log):
//   GET .../links/{fileID} -> DriveLink{FileProperties.ContentKeyPacket
//     (unarmored b64 bare PKESK), ActiveRevision.ID}
//   GET .../files/{fileID}/revisions -> {Revisions:[{ID, ManifestSignature …}]}
//   GET .../files/{fileID}/revisions/{revID} -> {Revision:{Blocks:[{Index,
//     Hash (b64 SHA-256 of ENCRYPTED bytes), Token (storage JWT),
//     URL (token in-path), BareURL (storage host), EncSignature}], …}}
//   GET {BareURL} (storage host, Pm-Storage-Token: Token, Bearer + X-Pm-Uid,
//     honest x-pm-appversion) -> octet-stream encrypted SED tag-18
//     packet (Size == wire Size; 77B for the 26B fixture).
// Semantics: Hash == sha256(storage bytes) — NOT plaintext (proven: the
// fixture Hash f854… != sha256(plaintext) 0532…). Decrypt mirrors
// FileUpload.encryptBlock (SED tag-18 v1 + literal ""); content key opens
// via FileUpload.openContentKey with the NODE candidates.

import CryptoKit
import Foundation

enum FileDownloadError: Error, Sendable, Equatable {
    case missingContentKey
    case missingRevision
    case badBlockHash(String)
    case hashMismatch(index: Int)
    case emptyBlockList
    case blockIndexGap
    /// A destination built from a remote name resolved outside the folder
    /// the user chose (path traversal / symlink escape) — F8.1-S5.
    case unsafeDestination
    /// ContentKeyPacketSignature present but invalid (F8.1-S2).
    case contentKeySignatureInvalid
    /// Revision has no ManifestSignature (F8.1-S2; C# SDK fails too).
    case manifestSignatureMissing
    /// ManifestSignature does not verify over the block hashes (F8.1-S2).
    case manifestSignatureInvalid
    /// A block's EncSignature does not verify (F8.1-S2).
    case blockSignatureInvalid(index: Int)
}

enum FileDownload {
    /// One fetched block, ready to verify + decrypt.
    struct FetchedBlock: Sendable {
        var index: Int
        /// Raw encrypted SED tag-18 packet (exact storage bytes).
        var encrypted: Data
        /// Expected base64 SHA-256 (wire `Hash`).
        var expectedHashB64: String
        /// Armored EncSignature (wire `EncSignature`); nil → not checked.
        var encSignature: String? = nil
    }

    /// Block-signature verification inputs (F8.1-S2): node candidates open
    /// the EncSignature, signer points are the allowed signers.
    struct BlockSignatureCheck: Sendable {
        var nodeCandidates: [DecryptCandidate]
        var signerPoints: [Data]
    }

    /// Verifies one block's SHA-256 against its wire hash (base64).
    /// Throws hashMismatch on ANY difference (fail-closed).
    static func verifyBlock(_ block: FetchedBlock) throws {
        guard let expected = Data(base64Encoded: block.expectedHashB64) else {
            throw FileDownloadError.badBlockHash(block.expectedHashB64)
        }
        let actual = Data(SHA256.hash(data: block.encrypted))
        guard actual == expected else {
            throw FileDownloadError.hashMismatch(index: block.index)
        }
    }

    /// Verifies + decrypts + reassembles blocks in index order.
    /// - `blocks`: fetched storage bytes with their wire hashes (any order).
    /// - `contentKey`: 32-byte session key from the ContentKeyPacket.
    /// Returns the exact original file bytes (byte-identical roundtrip).
    /// - `signatures`: when set, every block carrying an EncSignature must
    ///   verify (`verifyBlockSignature`) — content integrity, fail closed.
    static func reassemble(
        blocks: [FetchedBlock],
        contentKey: Data,
        signatures: BlockSignatureCheck? = nil
    ) throws -> Data {
        guard !blocks.isEmpty else { return Data() }
        let ordered = blocks.sorted { $0.index < $1.index }
        // Contiguity check: 1-based, no gaps (server lists are dense).
        for (i, b) in ordered.enumerated() {
            guard b.index == i + 1 else { throw FileDownloadError.blockIndexGap }
        }
        var out = Data()
        for b in ordered {
            try verifyBlock(b)
            let plain = try FileUpload.decryptBlock(b.encrypted, contentKey: contentKey)
            if let signatures {
                try verifyBlockSignature(
                    b.encSignature, index: b.index, plaintext: plain,
                    encryptedHash: Data(SHA256.hash(data: b.encrypted)), check: signatures
                )
            }
            out.append(plain)
        }
        return out
    }

    /// Convenience roundtrip for tests: splits + encrypts via FileUpload,
    /// then reassembles through the download path (proves byte-identity
    /// including multi-block ordering and hash checks).
    static func roundtrip(
        data: Data,
        blockSize: Int = FileUpload.defaultBlockSize,
        contentKey: Data? = nil
    ) throws -> Data {
        let key = contentKey ?? Data((0..<FileUpload.sessionKeyLength).map { _ in UInt8.random(in: .min ... .max) })
        guard key.count == FileUpload.sessionKeyLength else { throw FileDownloadError.missingContentKey }
        let chunks = FileUpload.splitBlocks(data, blockSize: blockSize)
        guard !chunks.isEmpty else { return Data() }
        var fetched: [FetchedBlock] = []
        for (i, chunk) in chunks.enumerated() {
            let enc = try FileUpload.encryptBlock(chunk, contentKey: key)
            let hash = try FileUpload.blockHash(enc)
            fetched.append(FetchedBlock(
                index: i + 1, encrypted: enc,
                expectedHashB64: hash.base64EncodedString()
            ))
        }
        // Exercise out-of-order tolerance: reverse before reassemble.
        return try reassemble(blocks: fetched.reversed(), contentKey: key)
    }

    // MARK: - signature verification (F8.1-S2)

    /// Manifest inputs accepted for a revision: thumbnail hashes (sorted by
    /// type) followed by the raw block hashes in index order — C# SDK
    /// Nodes/Download/RevisionReader.cs `ReadAsync` (thumbnails
    /// `OrderBy(t => t.Type)` then block digests) + `VerifyManifestAsync`;
    /// Proton-API-Bridge file_upload.go appends `sha256(encData)` per block.
    /// Also accepted: blocks preceded by the legacy single ThumbnailHash,
    /// and blocks only (thumbnails are never downloaded here, so dropping
    /// them cannot hide a change to the file's bytes; covers revisions whose
    /// thumbnail list did not decode and Nucleon uploads, which have none).
    static func manifestVariants(
        blockHashesB64: [String],
        thumbnails: [RevisionThumbnail],
        legacyThumbnailHash: String?
    ) throws -> [Data] {
        func raw(_ b64: String) throws -> Data {
            guard let d = Data(base64Encoded: b64) else { throw FileDownloadError.badBlockHash(b64) }
            return d
        }
        let blocks = try blockHashesB64.map(raw).reduce(Data(), +)
        var variants: [Data] = []
        if !thumbnails.isEmpty {
            let thumbs = try thumbnails.sorted { $0.type < $1.type }.map { try raw($0.hash) }
            variants.append(thumbs.reduce(Data(), +) + blocks)
        }
        if let legacy = legacyThumbnailHash, !legacy.isEmpty, let d = Data(base64Encoded: legacy) {
            variants.append(d + blocks)
        }
        variants.append(blocks)
        return variants
    }

    /// Manifest check (content integrity): missing → `.manifestSignatureMissing`
    /// (C# SDK throws `CompletedDownloadManifestVerificationException` on
    /// `NotSigned` too); invalid or weak hash → `.manifestSignatureInvalid`.
    /// A foreign signer (`.noVerifier`, shared content) is returned, not
    /// thrown — its public keys are not fetched (see report).
    @discardableResult
    static func verifyManifest(
        signature: String?,
        variants: [Data],
        signerPoints: [Data]
    ) throws -> SignatureVerification.Outcome {
        let outcome = SignatureVerification.detached(
            armored: signature, over: variants, signerPoints: signerPoints
        )
        switch outcome {
        case .valid, .noVerifier: return outcome
        case .missing: throw FileDownloadError.manifestSignatureMissing
        case .invalid, .weakHash: throw FileDownloadError.manifestSignatureInvalid
        }
    }

    /// ContentKeyPacketSignature check. Upstream signs the SESSION KEY bytes
    /// (go-proton-api link_types.go `GetSessionKey`: `nodeKR.VerifyDetached(
    /// key.Key)`; C# SDK NodeCrypto.cs `DecryptContentKey`:
    /// `Verify(contentKey.Export())` with node key + SignatureEmail keys).
    /// Nucleon F4.3 uploads signed the raw PKESK bytes
    /// (FileUpload.signContentKeyPacket), so that variant is accepted too.
    /// The signature is OPTIONAL upstream (C# `ContentKeySignature` is
    /// nullable → `NotSigned` is a non-fatal authorship failure): missing /
    /// foreign signer is returned; invalid or weak → throws.
    @discardableResult
    static func verifyContentKey(
        signature: String?,
        sessionKey: Data,
        packetRaw: Data?,
        signerPoints: [Data]
    ) throws -> SignatureVerification.Outcome {
        var variants = [sessionKey]
        if let packetRaw { variants.append(packetRaw) }
        let outcome = SignatureVerification.detached(
            armored: signature, over: variants, signerPoints: signerPoints
        )
        switch outcome {
        case .valid, .missing, .noVerifier: return outcome
        case .invalid, .weakHash: throw FileDownloadError.contentKeySignatureInvalid
        }
    }

    /// Block EncSignature check: the armored message (encrypted to the node
    /// key) carries a detached signature packet. Upstream signs the
    /// PLAINTEXT block with the address key (Proton-API-Bridge
    /// file_upload.go `DefaultAddrKR.SignDetachedEncrypted(dataPlainMessage,
    /// nodeKR)`, verified in crypto.go `decryptBlockIntoBuffer` with the
    /// SignatureEmail keyring + nodeKR); Nucleon F4.3 uploads signed the raw
    /// encrypted-block hash (FileUpload.blockSignaturePacket) — both
    /// accepted. Missing EncSignature or foreign signer → not checked (the
    /// C# SDK BlockDownloader does not verify blocks at all; the manifest
    /// covers every block hash). Invalid, undecryptable or weak → throws.
    static func verifyBlockSignature(
        _ encSignature: String?,
        index: Int,
        plaintext: Data,
        encryptedHash: Data,
        check: BlockSignatureCheck
    ) throws {
        guard let encSignature, !encSignature.isEmpty else { return }
        guard let literal = try? MessageDecrypt.decrypt(armored: encSignature, candidates: check.nodeCandidates) else {
            throw FileDownloadError.blockSignatureInvalid(index: index)
        }
        var sigBytes = literal
        if literal.starts(with: Data("-----BEGIN".utf8)),
           let text = String(data: literal, encoding: .utf8),
           let decoded = try? Armor.decode(text) {
            sigBytes = decoded
        }
        let bodies = ((try? PGPPackets.parse(sigBytes)) ?? []).filter { $0.tag == 2 }.map(\.body)
        let outcome = SignatureVerification.check(
            signatureBodies: bodies, over: [plaintext, encryptedHash], signerPoints: check.signerPoints
        )
        switch outcome {
        case .valid, .noVerifier: return
        case .missing, .invalid, .weakHash: throw FileDownloadError.blockSignatureInvalid(index: index)
        }
    }

    // MARK: - destination planning (pure Foundation)

    /// Best-effort conflict-free destination: `name`, then `name (1)`,
    /// `name (2)`, … (matches the upload-side convention; never overwrites
    /// silently). Extension-aware: "a.txt" → "a (1).txt".
    /// `name` must already be a single safe component (SafeFilename).
    static func uniqueDestination(in directory: URL, name: String) -> URL {
        let fm = FileManager.default
        let candidate = directory.appendingPathComponent(name, isDirectory: false)
        guard fm.fileExists(atPath: candidate.path) else { return candidate }
        for n in 1...1000 {
            // Keep the suffixed name within the 255-byte limit.
            let suffix = " (\(n))"
            let base = SafeFilename.capped(
                name, maxBytes: SafeFilename.maxBytes - suffix.utf8.count
            )
            let stem = (base as NSString).deletingPathExtension
            let ext = (base as NSString).pathExtension
            let suffixed = ext.isEmpty ? "\(stem)\(suffix)" : "\(stem)\(suffix).\(ext)"
            let url = directory.appendingPathComponent(suffixed, isDirectory: false)
            guard fm.fileExists(atPath: url.path) else { return url }
        }
        return candidate // unreachable in practice; never overwrite loop
    }

    /// Conflict-free FILE destination for a remote (untrusted) name:
    /// sanitized via SafeFilename, then verified to stay inside `root` (the
    /// folder the user chose). Throws `.unsafeDestination` otherwise.
    static func safeFileDestination(
        in directory: URL, remoteName: String, fallback: String, root: URL
    ) throws -> URL {
        let name = SafeFilename.sanitize(remoteName, fallback: fallback)
        let dest = uniqueDestination(in: directory, name: name)
        guard SafeFilename.contained(dest, in: root) else {
            throw FileDownloadError.unsafeDestination
        }
        return dest
    }

    /// Local subfolder for a remote (untrusted) folder name, same checks as
    /// safeFileDestination. Folders merge (no " (n)" suffix), as before.
    static func safeSubdirectory(
        in directory: URL, remoteName: String, fallback: String, root: URL
    ) throws -> URL {
        let name = SafeFilename.sanitize(remoteName, fallback: fallback)
        let dest = directory.appendingPathComponent(name, isDirectory: true)
        guard SafeFilename.contained(dest, in: root) else {
            throw FileDownloadError.unsafeDestination
        }
        return dest
    }

    /// Atomic write: temp `*.nucleon-part` in the destination directory +
    /// rename (TRANSFERS.md §2.2). Creates intermediate directories.
    static func atomicWrite(_ data: Data, to destination: URL) throws {
        let dir = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        let part = dir
            .appendingPathComponent(destination.lastPathComponent + ".nucleon-part")
        try data.write(to: part, options: .atomic)
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.moveItem(at: part, to: destination)
    }
}
