// Nucleon Transfer — live upload adapter (F4.4; S1.2 key resolver).
// Bridges TransferQueue's offline-tested core to the live-verified F4.2/F4.3
// path (DriveClient.createFolder / uploadFile). Key material is resolved by
// the session's shared NodeKeyResolver (share/node memo + parent-chain
// walk), so uploads work under ANY existing remote folder — not just the
// root or session-created ones (P5/P6 fixed). Folder memo is per-session
// (in-memory, on the resolver); file jobs whose remote parent was created
// in a previous session now resolve remotely instead of failing — the
// "re-add" fallback is gone.

import Foundation

/// Live TransferUploader + RemoteFolderCreator over DriveClient.
actor DriveUploadAdapter: TransferUploader, RemoteFolderCreator {
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver

    init(drive: DriveClient, addressKeys: [KeyringCache.UnlockedKey], resolver: NodeKeyResolver) {
        self.drive = drive
        self.addressKeys = addressKeys
        self.resolver = resolver
    }

    // MARK: - TransferUploader

    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void
    ) async throws -> String? {
        try await upload(job: job, progress: progress, events: TransferUploadEvents())
    }

    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void,
        events: TransferUploadEvents
    ) async throws -> String? {
        let url = try localFileURL(for: job)
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw TransferFailure.permanent("cannot read \(job.fileName): \(error.localizedDescription)")
        }
        let parent = try await resolver.folder(shareID: job.shareID, linkID: job.parentLinkID)
        let mtime = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
        await progress(0)
        // Whole-file, sequential blocks (F4.3 verified path — no per-block
        // progress yet; the queue jumps 0 → total per file at F4.4).
        let done = try await drive.uploadFile(
            shareID: job.shareID,
            parentLinkID: job.parentLinkID,
            fileName: job.fileName,
            data: data,
            parentKeys: parent.keys,
            parentHashKey: parent.hashKey,
            addressKeys: addressKeys,
            addressID: parent.addressID,
            signatureAddress: parent.signatureEmail,
            signatureEmail: parent.signatureEmail,
            modificationTime: mtime,
            clientUID: job.clientUID,
            knownDraftLinkID: job.draftLinkID,
            onDraftCreated: events.draftCreated
        )
        await progress(Int64(data.count))
        return done.linkID
    }

    // MARK: - RemoteFolderCreator

    /// Creates `name` under `parentLinkID`, or MERGES when the name is
    /// already taken by a folder (F7.1 R4 — same as the Proton web UI and
    /// the Finder copying into an existing folder). One create attempt;
    /// on the duplicate-name answer (FolderConflictPolicy.isDuplicateName,
    /// code 2500) the parent's children are listed and decrypted exactly
    /// like DriveListing.children does (shared decryptedChildren helper),
    /// and FolderConflictPolicy.resolve picks reuse-vs-fail. Any other
    /// error rethrows as-is — no suffix renaming, ever.
    func ensureFolder(name: String, parentLinkID: String, shareID: String) async throws -> String {
        let parent = try await resolver.folder(shareID: shareID, linkID: parentLinkID)
        let linkID: String
        do {
            let created = try await drive.createFolder(
                shareID: shareID,
                parentLinkID: parentLinkID,
                name: name,
                parentKeys: parent.keys,
                parentHashKey: parent.hashKey,
                addressKeys: addressKeys,
                signatureAddress: parent.signatureEmail,
                signatureEmail: parent.signatureEmail
            )
            linkID = created.linkID
        } catch {
            guard FolderConflictPolicy.isDuplicateName(error) else { throw error }
            let children = try await DriveListing.decryptedChildren(
                drive: drive, resolver: resolver,
                shareID: shareID, linkID: parentLinkID
            )
            switch FolderConflictPolicy.resolve(name: name, children: children) {
            case let .reuse(existingID):
                linkID = existingID
            case let .fail(message):
                throw TransferFailure.permanent(message)
            }
        }
        // Resolve the folder context (getLink + unlock + hash key — its
        // link is already in the resolver's cache after a merge listing)
        // and register it, so later uploads into it hit the memo.
        let ctx = try await resolver.folder(shareID: shareID, linkID: linkID)
        await resolver.register(createdFolder: ctx)
        return linkID
    }

    // MARK: - local files

    /// Prefers the enqueue-time path; falls back to the security-scoped
    /// bookmark (survives moves/renames within a session grant).
    private func localFileURL(for job: TransferJob) throws -> URL {
        if FileManager.default.fileExists(atPath: job.localPath) {
            return URL(fileURLWithPath: job.localPath)
        }
        if let bookmark = job.localBookmark {
            var stale = false
            if let url = try? URL(
                resolvingBookmarkData: bookmark,
                options: .withSecurityScope,
                relativeTo: nil,
                bookmarkDataIsStale: &stale
            ), FileManager.default.fileExists(atPath: url.path) {
                return url
            }
        }
        throw TransferFailure.permanent("local file missing — re-add \(job.fileName)")
    }
}
