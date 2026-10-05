// Nucleon Transfer — live upload adapter (F4.4; S1.2 key resolver).
// Bridges TransferQueue's offline-tested core to the live-verified F4.2/F4.3
// path (DriveClient.createFolder / uploadFile). Key material is resolved by
// the session's shared NodeKeyResolver (share/node memo + parent-chain
// walk), so uploads work under ANY existing remote folder — not just the
// root or session-created ones (P5/P6 fixed). Folder memo is per-session
// (in-memory, on the resolver); file jobs whose remote parent was created
// in a previous session now resolve remotely instead of failing — the
// "re-add" fallback is gone.
// F8.2-R4: the job's local file is opened through LocalFileAccess —
// bookmark resolved + security scope started for the job's duration (and
// stopped on every exit); a stale bookmark is re-created and persisted.
// F8.2 review: a retry whose previous attempt already sent the commit first
// verifies the draft (UploadCommitVerification — lost commit response), and
// cancelled/removed jobs' drafts are discarded via `discardDraft`.
// F8.3-P2: the file streams (FileBlockSource + StreamingUpload) with
// per-block progress instead of being read whole.

import Foundation

/// Live TransferUploader + RemoteFolderCreator over DriveClient.
actor DriveUploadAdapter: TransferUploader, RemoteFolderCreator {
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver
    private let files: LocalFileAccess

    init(
        drive: DriveClient,
        addressKeys: [KeyringCache.UnlockedKey],
        resolver: NodeKeyResolver,
        files: LocalFileAccess = .live
    ) {
        self.drive = drive
        self.addressKeys = addressKeys
        self.resolver = resolver
        self.files = files
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
        // Lost commit response: the previous attempt's revision may be
        // live already — then the job is done, nothing is re-uploaded.
        let drive = self.drive
        let shareID = job.shareID
        if let committed = await UploadCommitVerification.alreadyCommitted(
            job: job,
            getLink: { try await drive.getLink(shareID: shareID, linkID: $0) }
        ) {
            await progress(job.bytesTotal)
            return committed
        }
        // F8.2-R4: resolve the bookmark and hold its security scope for
        // the whole job; `defer` balances it on success, failure and
        // cancellation alike.
        let opened = try files.open(job)
        defer { files.close(opened) }
        if let refreshed = opened.refreshedBookmark {
            await events.bookmarkRefreshed(refreshed)
        }
        let url = opened.url
        // F8.3-P2: streamed — the file is read block by block (pread) while
        // blocks are encrypted, signed and sent; nothing whole-file is
        // held in memory. The source keeps its descriptor open for the job
        // (inside the security scope above).
        let source: FileBlockSource
        do {
            source = try FileBlockSource(url: url)
        } catch {
            // Name-free token (F8.4-U2 / review): the row already shows
            // the file name; the copy is localized at display time.
            throw TransferFailure.permanent(UserFacingError.Copy.fileUnreadable.token)
        }
        let parent = try await resolver.folder(shareID: job.shareID, linkID: job.parentLinkID)
        let mtime = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
        await progress(0)
        do {
            let done = try await drive.uploadFile(
                shareID: job.shareID,
                parentLinkID: job.parentLinkID,
                fileName: job.fileName,
                source: source,
                parentKeys: parent.keys,
                parentHashKey: parent.hashKey,
                addressKeys: addressKeys,
                addressID: parent.addressID,
                signatureAddress: parent.signatureEmail,
                signatureEmail: parent.signatureEmail,
                modificationTime: mtime,
                clientUID: job.clientUID,
                knownDraftLinkID: job.draftLinkID,
                onDraftCreated: events.draftCreated,
                onCommitSending: events.commitSending,
                progress: progress // per uploaded block
            )
            await progress(source.size)
            return done.linkID
        } catch UploadSourceError.changedDuringUpload {
            // F8.3 review: written/appended/replaced while it uploaded —
            // the draft was discarded; a retry now would race the writer.
            throw TransferFailure.permanent(UploadSourceError.changedMessage)
        } catch is UploadSourceError {
            // The file changed or became unreadable mid-upload: retrying
            // the same job would hit the same file — permanent.
            throw TransferFailure.permanent(UserFacingError.Copy.fileUnreadable.token)
        }
    }

    /// Deletes a cancelled/removed job's draft (delete_multiple on its
    /// parent — DriveClient.deleteDraft, the FileDraftFlow path), never a
    /// revision that got committed (UploadCommitVerification.discardDraft).
    func discardDraft(job: TransferJob) async throws {
        let drive = self.drive
        let shareID = job.shareID
        let parentLinkID = job.parentLinkID
        try await UploadCommitVerification.discardDraft(
            job: job,
            getLink: { try await drive.getLink(shareID: shareID, linkID: $0) },
            delete: { try await drive.deleteDraft(shareID: shareID, parentLinkID: parentLinkID, linkID: $0) }
        )
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
}
