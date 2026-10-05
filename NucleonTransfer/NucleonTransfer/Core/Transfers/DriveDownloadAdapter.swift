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
//   manifest signature (F8.1-S2) -> FileDownload.downloadToPart (F8.3-P2:
//   blocks fetched in parallel, hash-verify + decrypt + block EncSignature
//   off this actor, written in order into a `.nucleon-part` with a reorder
//   window of maxConcurrentBlocks — memory bounded, not file-sized) ->
//   DownloadPlacement.place (reserved conflict-free name, exclusive
//   rename — never replaces an existing item, F8.2-R5).
// Folders download recursively (children listing + name decrypt), preserving
// structure — including the folder itself: "Vacation" lands as
// <destination>/Vacation/… ("Vacation (1)" if that exists, F8.2-R6); files
// within one folder download with bounded parallelism.
// Cancellation (F8.2-R5): checked between blocks and between files; a
// cancelled file never leaves its temp file behind.

import Foundation

/// Live file/folder download over DriveClient.
actor DriveDownloadAdapter {
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver
    /// Name reservations for every download through this adapter (one
    /// adapter per batch): siblings racing in parallel never collide.
    private let placement = DownloadPlacement()

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

    /// Downloads one FILE link into a new part file in `directory`
    /// (F8.3-P2: streamed — FileDownload.downloadToPart; the caller places
    /// it with DownloadPlacement.place). `partName` is the (untrusted)
    /// remote name, sanitized for the part file's stem. Reports per-block
    /// completion (0...blocks.count) for progress UI.
    func downloadFileToPart(
        shareID: String,
        link: DriveLink,
        parentKeys: [KeyringCache.UnlockedKey],
        directory: URL,
        partName: String,
        progress: @Sendable (Int, Int) async -> Void = { _, _ in }
    ) async throws -> (part: URL, size: Int64) {
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
        // Signer sets come from server-claimed emails, so they always
        // include the node key (FileDownload.trustedSigners): `.noVerifier`
        // can never pass.
        let nodePoints = DecryptChain.edPoints(nodeKeys)
        try FileDownload.verifyContentKey(
            signature: link.fileProperties?.contentKeyPacketSignature,
            sessionKey: contentKey, packetRaw: Data(base64Encoded: ckp),
            signerPoints: FileDownload.trustedSigners(
                claimedEmail: link.signatureEmail, nodePoints: nodePoints,
                addressKeys: addressKeys
            ).points
        )
        let revisionID = try await revisionID(shareID: shareID, link: link)
        let revision = try await drive.getRevision(
            shareID: shareID, linkID: link.linkID, revisionID: revisionID
        )
        let ordered = revision.blocks.sorted { $0.index < $1.index }
        // Manifest BEFORE any block is fetched: the signed hash list pins
        // every block (downloadToPart checks each block against them).
        // Signer: the revision's SignatureEmail address keys (C# SDK
        // RevisionReader.cs VerifyManifestAsync), else the link author's;
        // the node key always. A foreign/unknown claimed email is NOT
        // trusted: only the node key or the user's own address keys can
        // then vouch for the manifest, otherwise the download stops.
        // Empty files are verified too (manifest over zero block hashes):
        // RevisionReader.ReadAsync has no empty-file short-circuit and
        // throws on NotSigned, and every uploader (Nucleon, Proton-API-Bridge)
        // signs the empty manifest.
        let revisionEmail = revision.signatureEmail ?? ""
        let signers = FileDownload.trustedSigners(
            claimedEmail: revisionEmail.isEmpty ? link.signatureEmail : revisionEmail,
            nodePoints: nodePoints, addressKeys: addressKeys
        )
        try FileDownload.verifyManifest(
            signature: revision.manifestSignature,
            variants: FileDownload.manifestVariants(
                blockHashesB64: ordered.map(\.hash),
                thumbnails: revision.thumbnails,
                legacyThumbnailHash: revision.thumbnailHash
            ),
            signerPoints: signers.points,
            claimResolved: signers.claimResolved
        )
        // Block EncSignatures: same trusted set (Proton-API-Bridge
        // file_download.go getSignatureVerificationKeyring: uploader's
        // address keys + node key). A 0-byte file has no blocks and yields
        // an empty part file (upload parity §1.4).
        let blockCheck = FileDownload.BlockSignatureCheck(
            nodeCandidates: nodeCandidates, signerPoints: signers.points
        )
        let drive = self.drive
        return try await FileDownload.downloadToPart(
            blocks: ordered, contentKey: contentKey, signatures: blockCheck,
            window: maxConcurrentBlocks, directory: directory,
            name: SafeFilename.sanitize(partName, fallback: link.linkID),
            fetch: { try await drive.downloadBlockBytes(block: $0) },
            progress: progress
        )
    }

    // MARK: - single file to disk (with per-block progress)

    /// Downloads one FILE link directly to `directory` (conflict-free name
    /// via DownloadPlacement: reservation + exclusive rename). Reports
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
        let name = (try? DecryptChain.decryptName(
            link, parentCandidates: parentKeys.compactMap(\.candidate)
        )) ?? link.linkID
        let file = try await downloadFileToPart(
            shareID: shareID, link: link, parentKeys: parentKeys,
            directory: directory, partName: name, progress: progress ?? { _, _ in }
        )
        return try await placement.place(
            part: file.part, in: directory, remoteName: name, fallback: link.linkID, root: directory
        )
    }

    // MARK: - recursive folder

    /// Downloads a remote FOLDER tree into a NEW folder named after it inside
    /// `destination` (F8.2-R6: never merged into an existing one), preserving
    /// structure. Returns downloaded file URLs.
    /// `linkID` may be a file (single download, straight into
    /// `destination`) or folder (recursive).
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
            let name = (try? DecryptChain.decryptName(
                link, parentCandidates: parentKeys.compactMap(\.candidate)
            )) ?? link.linkID
            let file = try await downloadFileToPart(
                shareID: shareID, link: link, parentKeys: parentKeys,
                directory: destination, partName: name
            )
            let dest = try await placement.place(
                part: file.part, in: destination, remoteName: name, fallback: link.linkID, root: destination
            )
            if let progress {
                await progress(dest.lastPathComponent, file.size, file.size)
            }
            return [dest]
        }
        let parentKeys = try await parentKeysFor(shareID: shareID, link: link)
        let name = (try? DecryptChain.decryptName(
            link, parentCandidates: parentKeys.compactMap(\.candidate)
        )) ?? link.linkID
        // Sanitized + contained in `destination` like every other remote
        // name (safeSubdirectory inside DownloadPlacement).
        let top = try await placement.makeTopLevelDirectory(
            in: destination, remoteName: name, fallback: link.linkID
        )
        return try await downloadFolder(
            shareID: shareID, folderLinkID: linkID, localDir: top,
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
        // files download with bounded parallelism. `name` is the RAW
        // decrypted (untrusted) name: DownloadPlacement sanitizes it
        // (SafeFilename), checks the result against `root`, and gives
        // case-only siblings distinct local names (F8.2-R5).
        struct NamedChild: Sendable {
            var link: DriveLink
            var name: String
        }
        let named = children.map { child in
            NamedChild(
                link: child,
                name: (try? DecryptChain.decryptName(
                    child, parentCandidates: candidates
                )) ?? child.linkID
            )
        }
        var out: [URL] = []
        // Subfolders first (structure before bytes, TRANSFERS.md §2.2).
        for child in named.filter({ $0.link.isFolder }) {
            try Task.checkCancellation()
            let subdir = try await placement.makeDirectory(
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
                group.addTask { [placement] in
                    let file = try await self.downloadFileToPart(
                        shareID: shareID, link: child.link,
                        parentKeys: folderKeys, directory: localDir,
                        partName: child.name
                    )
                    let dest = try await placement.place(
                        part: file.part, in: localDir, remoteName: child.name,
                        fallback: child.link.linkID, root: root
                    )
                    if let progress {
                        await progress(dest.lastPathComponent, file.size, file.size)
                    }
                    return [dest]
                }
            }
            while next < files.count, inFlight < maxConcurrentFiles {
                submit(files[next]); next += 1; inFlight += 1
            }
            while next < files.count || inFlight > 0 {
                try Task.checkCancellation()
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
