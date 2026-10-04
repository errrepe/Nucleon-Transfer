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
}

enum FileDownload {
    /// One fetched block, ready to verify + decrypt.
    struct FetchedBlock: Sendable {
        var index: Int
        /// Raw encrypted SED tag-18 packet (exact storage bytes).
        var encrypted: Data
        /// Expected base64 SHA-256 (wire `Hash`).
        var expectedHashB64: String
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
    static func reassemble(
        blocks: [FetchedBlock],
        contentKey: Data
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
            out.append(try FileUpload.decryptBlock(b.encrypted, contentKey: contentKey))
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
