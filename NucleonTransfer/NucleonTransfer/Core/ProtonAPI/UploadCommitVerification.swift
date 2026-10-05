// Nucleon Transfer — lost-commit verification + draft discard (F8.2 review).
// A commit request can reach the server while its response is lost
// (timeout, dropped connection, cancellation). Retrying then fails with 2500
// (our own committed file holds the name) and the job ended `.failed` even
// though the upload succeeded. After any commit failure — and before a retry
// re-uploads a job whose commit was already sent — the draft's link is
// looked up: ACTIVE with our revision as its active revision means the
// upload is done.
//
// Upstream reference: ProtonDriveApps/sdk
//   client/js/src/internal/upload/manager.ts `commitDraft` — on a commit
//   error it calls `apiService.isRevisionUploaded(nodeRevisionUid)` and
//   swallows the error when that answers true;
//   client/js/src/internal/upload/apiService.ts `isRevisionUploaded` —
//   `link.Link.State === 1 && link.File?.ActiveRevision?.RevisionID === revisionId`
//   (v2 volume links endpoint; we use the share-scoped GET link, which
//   returns the same State + FileProperties.ActiveRevision).

import Foundation

enum UploadCommitVerification {
    /// Link state ACTIVE (DriveLink.state: 0 draft, 1 active, …).
    static let activeState = 1
    /// Link state DRAFT.
    static let draftState = 0

    /// The SDK's `isRevisionUploaded` predicate, plus a parent check (the
    /// link must still live where the job uploads to).
    static func isCommitted(_ link: DriveLink, revisionID: String, parentLinkID: String?) -> Bool {
        guard link.state == activeState,
              link.fileProperties?.activeRevision?.id == revisionID
        else { return false }
        if let parentLinkID, let actual = link.parentLinkID, actual != parentLinkID { return false }
        return true
    }

    /// Result of a commit attempt that may have lost its response.
    enum CommitOutcome: Sendable {
        /// Sent and answered OK, or failed but the revision IS active.
        case committed
        /// The revision is verifiably not committed: the draft can go.
        case notCommitted(any Error)
        /// The commit failed and verification could not answer: the draft
        /// may be a committed file — never delete it blindly (the queue's
        /// next attempt verifies again, `alreadyCommitted`).
        case unknown(any Error)
    }

    /// Sends the commit; on failure asks `isCommitted` (the SDK flow).
    static func commit(
        send: @Sendable () async throws -> Void,
        isCommitted: @Sendable () async throws -> Bool
    ) async -> CommitOutcome {
        do {
            try await send()
            return .committed
        } catch let commitError {
            // Like the SDK: a failed check surfaces the commit's error,
            // not the checking one.
            guard let committed = try? await isCommitted() else { return .unknown(commitError) }
            return committed ? .committed : .notCommitted(commitError)
        }
    }

    /// Retry pre-check: a job whose previous attempt sent the commit is
    /// verified first. Returns the committed LinkID, or nil to upload
    /// again (lookup failure included — FileDraftFlow then deletes the
    /// stale draft if it is still one, and a real file answers 2500).
    static func alreadyCommitted(
        job: TransferJob,
        getLink: @Sendable (_ linkID: String) async throws -> DriveLink
    ) async -> String? {
        guard job.draftCommitSent,
              let linkID = job.draftLinkID, let revisionID = job.draftRevisionID
        else { return nil }
        guard let link = try? await getLink(linkID),
              isCommitted(link, revisionID: revisionID, parentLinkID: job.parentLinkID)
        else { return nil }
        return linkID
    }

    /// Discards a cancelled/removed job's draft. Without a sent commit the
    /// link can only be a draft: delete it. With one, delete only when the
    /// lookup still shows a DRAFT — a committed revision is the user's file
    /// now and stays. Throws when the draft may still exist.
    static func discardDraft(
        job: TransferJob,
        getLink: @Sendable (_ linkID: String) async throws -> DriveLink,
        delete: @Sendable (_ linkID: String) async throws -> Void
    ) async throws {
        guard let linkID = job.draftLinkID else { return }
        if job.draftCommitSent {
            let link = try await getLink(linkID)
            guard link.state == draftState else { return }
        }
        try await delete(linkID)
    }
}
