// Nucleon Transfer — live download adapter (F5; S1.2 key resolver).
// Bridges the offline-tested FileDownload core to DriveClient. Key material
// is resolved by the session's shared NodeKeyResolver (share/node memo +
// parent-chain walk + listing cache via `remember`), replacing this actor's
// own shareKeys/nodes/roots dictionaries (P6).
//
// Flow per file (rclone-captured /tmp/f5ref):
//   getLink -> unlockNode (parent candidates + SignatureEmail signer points,
//   fail-closed) -> openContentKey (node candidates) + content-key signature
//   -> getRevision (activeRevision.ID, fallback: listRevisions last) ->
//   manifest signature (F8.1-S2) -> download blocks in parallel (TaskGroup,
//   max 4) -> FileDownload.reassemble (hash-verify + decrypt + block
//   EncSignature) ->
//   atomicWrite to a conflict-free destination.
// Folders download recursively (children listing + name decrypt), preserving
// structure; files within one folder download with bounded parallelism.

import Foundation

/// Live file/folder download over DriveClient.
actor DriveDownloadAdapter {
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver

    /// Max parallel block fetches per file (TRANSFERS.md §1.5: bounded).
    var maxConcurrentBlocks = 4
    /// Max parallel file downloads per folder.
    var maxConcurrentFiles = 4

    init(drive: DriveClient, addressKeys: [KeyringCache.UnlockedKey], resolver: NodeKeyResolver) {
        self.drive = drive
        self.addressKeys = addressKeys
        self.resolver = resolver
    }

    // MARK: - single file

    /// Downloads one FILE link's bytes (no disk I/O here — caller writes).
    /// Reports per-block completion (0...blocks.count) for progress UI.
    func downloadFileBytes(
        shareID: String,
        link: DriveLink,
        parentKeys: [KeyringCache.UnlockedKey],
        progress: (@Sendable (Int, Int) async -> Void)? = nil
    ) async throws -> Data {
        let nodeKeys = try DecryptChain.unlockNode(
            link, parentCandidates: parentKeys.compactMap(\.candidate),
            signerPoints: DecryptChain.nodeSignerPoints(
                link, parentKeys: parentKeys, addressKeys: addressKeys
            )
        )
        guard let ckp = link.fileProperties?.contentKeyPacket, !ckp.isEmpty else {
            throw FileDownloadError.missingContentKey
        }
        let nodeCandidates = nodeKeys.compactMap(\.candidate)
        let (cipher, contentKey) = try FileUpload.openContentKey(
            ckp, nodeCandidates: nodeCandidates
        )
        guard cipher == FileUpload.sessionCipher || [7, 8, 9].contains(cipher) else {
            throw FileDownloadError.missingContentKey
        }
        // F8.1-S2 content integrity: node key + the link author's address
        // keys may sign the content key (C# SDK NodeCrypto.cs
        // GetContentKeyAndHashKeyVerificationKeyRing).
        let nodePoints = DecryptChain.edPoints(nodeKeys)
        try FileDownload.verifyContentKey(
            signature: link.fileProperties?.contentKeyPacketSignature,
            sessionKey: contentKey, packetRaw: Data(base64Encoded: ckp),
            signerPoints: nodePoints + SignatureVerification.signerPoints(
                claimedEmail: link.signatureEmail, addressKeys: addressKeys,
                anonymousFallback: []
            )
        )
        let revisionID = try await revisionID(shareID: shareID, link: link)
        let revision = try await drive.getRevision(
            shareID: shareID, linkID: link.linkID, revisionID: revisionID
        )
        let ordered = revision.blocks.sorted { $0.index < $1.index }
        // Manifest BEFORE any block is fetched: the signed hash list pins
        // every block (reassemble then checks bytes against those hashes).
        // Signer: the revision's SignatureEmail address keys, else the node
        // key (C# SDK RevisionReader.cs VerifyManifestAsync); the link
        // author's keys are also accepted when the revision names no email.
        let revisionEmail = revision.signatureEmail ?? ""
        let manifestSigners = revisionEmail.isEmpty
            ? nodePoints + SignatureVerification.signerPoints(
                claimedEmail: link.signatureEmail, addressKeys: addressKeys,
                anonymousFallback: []
            )
            : SignatureVerification.signerPoints(
                claimedEmail: revisionEmail, addressKeys: addressKeys,
                anonymousFallback: nodePoints
            )
        try FileDownload.verifyManifest(
            signature: revision.manifestSignature,
            variants: FileDownload.manifestVariants(
                blockHashesB64: ordered.map(\.hash),
                thumbnails: revision.thumbnails,
                legacyThumbnailHash: revision.thumbnailHash
            ),
            signerPoints: manifestSigners
        )
        guard !ordered.isEmpty else {
            return Data() // 0-byte file: no blocks (upload parity §1.4)
        }
        // Block EncSignatures: uploader's address keys + node key
        // (Proton-API-Bridge file_download.go getSignatureVerificationKeyring).
        let blockCheck = FileDownload.BlockSignatureCheck(
            nodeCandidates: nodeCandidates,
            signerPoints: nodePoints + SignatureVerification.signerPoints(
                claimedEmail: revisionEmail.isEmpty ? link.signatureEmail : revisionEmail,
                addressKeys: addressKeys, anonymousFallback: []
            )
        )
        var fetched = [FileDownload.FetchedBlock?](repeating: nil, count: ordered.count)
        try await withThrowingTaskGroup(of: (Int, FileDownload.FetchedBlock).self) { group in
            var next = 0
            var inFlight = 0
            func submit(_ i: Int) {
                let block = ordered[i]
                group.addTask {
                    let bytes = try await self.drive.downloadBlockBytes(block: block)
                    return (i, FileDownload.FetchedBlock(
                        index: block.index, encrypted: bytes,
                        expectedHashB64: block.hash,
                        encSignature: block.encSignature
                    ))
                }
            }
            while next < ordered.count, inFlight < maxConcurrentBlocks {
                submit(next); next += 1; inFlight += 1
            }
            var done = 0
            while done < ordered.count {
                let (i, fb) = try await group.next()!
                fetched[i] = fb
                done += 1
                inFlight -= 1
                if let progress { await progress(done, ordered.count) }
                if next < ordered.count {
                    submit(next); next += 1; inFlight += 1
                }
            }
        }
        return try FileDownload.reassemble(
            blocks: fetched.compactMap { $0 }, contentKey: contentKey,
            signatures: blockCheck
        )
    }

    // MARK: - single file to disk (with per-block progress)

    /// Downloads one FILE link directly to `directory` (conflict-free name
    /// via FileDownload.uniqueDestination + atomic write). Reports
    /// (doneBlocks, totalBlocks) as blocks complete.
    func downloadSingleFile(
        shareID: String,
        linkID: String,
        directory: URL,
        progress: (@Sendable (Int, Int) async -> Void)? = nil
    ) async throws -> URL {
        let link = try await drive.getLink(shareID: shareID, linkID: linkID)
        await resolver.remember([link])
        guard !link.isFolder else {
            throw FileDownloadError.missingRevision
        }
        let parentKeys = try await parentKeysFor(shareID: shareID, link: link)
        let bytes = try await downloadFileBytes(
            shareID: shareID, link: link, parentKeys: parentKeys,
            progress: progress
        )
        let name = (try? DecryptChain.decryptName(
            link, parentCandidates: parentKeys.compactMap(\.candidate)
        )) ?? link.linkID
        let dest = try FileDownload.safeFileDestination(
            in: directory, remoteName: name, fallback: link.linkID, root: directory
        )
        try FileDownload.atomicWrite(bytes, to: dest)
        return dest
    }

    // MARK: - recursive folder

    /// Downloads a remote FOLDER tree into `destination` (created if needed),
    /// preserving structure. Returns downloaded file URLs.
    /// `linkID` may be a file (single download) or folder (recursive).
    func downloadTree(
        shareID: String,
        linkID: String,
        destination: URL,
        progress: (@Sendable (String, Int64, Int64) async -> Void)? = nil
    ) async throws -> [URL] {
        let link = try await drive.getLink(shareID: shareID, linkID: linkID)
        await resolver.remember([link])
        if !link.isFolder {
            let parentKeys = try await parentKeysFor(shareID: shareID, link: link)
            let bytes = try await downloadFileBytes(
                shareID: shareID, link: link, parentKeys: parentKeys
            )
            let name = (try? DecryptChain.decryptName(
                link, parentCandidates: parentKeys.compactMap(\.candidate)
            )) ?? link.linkID
            let dest = try FileDownload.safeFileDestination(
                in: destination, remoteName: name, fallback: link.linkID, root: destination
            )
            try FileDownload.atomicWrite(bytes, to: dest)
            if let progress {
                await progress(dest.lastPathComponent, Int64(bytes.count), Int64(bytes.count))
            }
            return [dest]
        }
        return try await downloadFolder(
            shareID: shareID, folderLinkID: linkID, localDir: destination,
            root: destination, progress: progress
        )
    }

    private func downloadFolder(
        shareID: String,
        folderLinkID: String,
        localDir: URL,
        root: URL,
        progress: (@Sendable (String, Int64, Int64) async -> Void)? = nil
    ) async throws -> [URL] {
        let folderKeys = try await resolver.nodeKeys(shareID: shareID, linkID: folderLinkID)
        let candidates = folderKeys.compactMap(\.candidate)
        let children = try await drive.listChildren(shareID: shareID, linkID: folderLinkID)
        // Listing already fetched the children's links — let the resolver
        // reuse them instead of re-getLinking each subfolder on recursion.
        await resolver.remember(children)
        try FileManager.default.createDirectory(
            at: localDir, withIntermediateDirectories: true
        )
        // Decrypt names first (cheap, local), then subfolders recurse and
        // files download with bounded parallelism. Names are sanitized
        // (SafeFilename) and every destination is checked against `root`.
        struct NamedChild: Sendable {
            var link: DriveLink
            var name: String
        }
        let named = children.map { child in
            NamedChild(
                link: child,
                name: SafeFilename.sanitize(
                    (try? DecryptChain.decryptName(
                        child, parentCandidates: candidates
                    )) ?? child.linkID,
                    fallback: child.linkID
                )
            )
        }
        var out: [URL] = []
        // Subfolders first (structure before bytes, TRANSFERS.md §2.2).
        for child in named.filter({ $0.link.isFolder }) {
            let subdir = try FileDownload.safeSubdirectory(
                in: localDir, remoteName: child.name,
                fallback: child.link.linkID, root: root
            )
            let got = try await downloadFolder(
                shareID: shareID, folderLinkID: child.link.linkID,
                localDir: subdir, root: root, progress: progress
            )
            out.append(contentsOf: got)
        }
        let files = named.filter { !$0.link.isFolder }
        try await withThrowingTaskGroup(of: [URL].self) { group in
            var next = 0
            var inFlight = 0
            func submit(_ child: NamedChild) {
                group.addTask {
                    let bytes = try await self.downloadFileBytes(
                        shareID: shareID, link: child.link,
                        parentKeys: folderKeys
                    )
                    let dest = try FileDownload.safeFileDestination(
                        in: localDir, remoteName: child.name,
                        fallback: child.link.linkID, root: root
                    )
                    try FileDownload.atomicWrite(bytes, to: dest)
                    if let progress {
                        await progress(child.name, Int64(bytes.count), Int64(bytes.count))
                    }
                    return [dest]
                }
            }
            while next < files.count, inFlight < maxConcurrentFiles {
                submit(files[next]); next += 1; inFlight += 1
            }
            while next < files.count || inFlight > 0 {
                if let got = try await group.next() {
                    out.append(contentsOf: got)
                    inFlight -= 1
                }
                while next < files.count, inFlight < maxConcurrentFiles {
                    submit(files[next]); next += 1; inFlight += 1
                }
            }
        }
        return out
    }

    // MARK: - key resolution (delegates to the shared NodeKeyResolver)

    private func revisionID(shareID: String, link: DriveLink) async throws -> String {
        if let id = link.fileProperties?.activeRevision?.id, !id.isEmpty {
            return id
        }
        let revs = try await drive.listRevisions(shareID: shareID, linkID: link.linkID)
        guard let last = revs.last else { throw FileDownloadError.missingRevision }
        return last.id
    }

    /// Parent candidates for a link's passphrase/name: the parent node's
    /// keys, or the share keyring when the link has no parent (parity with
    /// the pre-resolver fallback).
    private func parentKeysFor(
        shareID: String, link: DriveLink
    ) async throws -> [KeyringCache.UnlockedKey] {
        if let parent = link.parentLinkID {
            return try await resolver.nodeKeys(shareID: shareID, linkID: parent)
        }
        return try await resolver.share(shareID).keys
    }
}
