// Nucleon Transfer — file-draft creation with stale-draft recovery (F8.2-R3).
// A retry after the draft was created used to fail with 2500 ("name already
// exists": our own leftover draft holds the name hash) and left orphan
// drafts behind. Each upload job now carries a ClientUID that is sent with
// the draft; before (and once after a 2500) creating it, the
// checkAvailableHashes probe's PendingHashes are matched against that
// ClientUID — or the draft LinkID persisted from an earlier attempt — and
// those stale drafts are deleted. Drafts of OTHER clients are never touched.
//
// Upstream references:
// - ClientUID on draft creation: ProtonDriveApps/sdk
//   client/cs/src/Proton.Drive.Sdk/Api/Files/FileCreationRequest.cs
//   (`[JsonPropertyName("ClientUID")] string? ClientUid`) and
//   client/js/src/internal/upload/apiService.ts `createDraft`
//   (`ClientUID: this.clientUid || null`).
// - Own-draft conflict → delete draft → create again:
//   client/js/src/internal/upload/manager.ts `handleConflictError`
//   (deletes only when the conflicting draft's ClientUID is ours).
// - Deleting a draft link = delete_multiple on its parent, skipping trash:
//   henrybear327/Proton-API-Bridge file_upload.go `handleRevisionConflict`
//   (`c.DeleteChildren(ctx, shareID, link.ParentLinkID, linkID)` →
//   go-proton-api link_folder.go `DeleteChildren`,
//   POST /drive/shares/{shareID}/folders/{linkID}/delete_multiple); the SDK
//   uses the v2 volume form of the same call (`deleteDraft`).

import Foundation

/// The three Drive calls the draft step needs (DriveClient in the app,
/// fakes in tests).
protocol FileDraftAPI: Sendable {
    func checkAvailableHashes(
        shareID: String, parentLinkID: String, hashes: [String]
    ) async throws -> (available: [String], pending: [PendingHash])
    func createFileDraft(
        shareID: String, request: CreateFileRequest
    ) async throws -> (linkID: String, revisionID: String)
    /// Permanently deletes a DRAFT link (state 0) under its parent.
    func deleteDraft(shareID: String, parentLinkID: String, linkID: String) async throws
}

enum FileDraftFlow {
    /// Pending drafts for `hash` that this job created earlier: same
    /// ClientUID, or the LinkID a previous attempt persisted (covers drafts
    /// made before ClientUID was sent — the server echoes `ClientUID:null`).
    static func ownStaleDrafts(
        pending: [PendingHash],
        hash: String,
        clientUID: String?,
        knownDraftLinkID: String?
    ) -> [String] {
        var out: [String] = []
        for p in pending {
            guard let linkID = p.linkID, !linkID.isEmpty else { continue }
            if let h = p.hash, h.lowercased() != hash.lowercased() { continue }
            let sameClient = clientUID.map { !$0.isEmpty && p.clientUID == $0 } ?? false
            let knownLink = knownDraftLinkID.map { $0 == linkID } ?? false
            if (sameClient || knownLink), !out.contains(linkID) { out.append(linkID) }
        }
        return out
    }

    /// Probe → delete own stale drafts → create. On a duplicate-name answer
    /// (2500) the probe runs once more (a draft may have appeared between
    /// probe and create, or the first delete failed); if it then lists one
    /// of OUR drafts, that draft is deleted and the create retried once.
    /// Anything else (a real file, another client's draft) rethrows.
    static func createDraft(
        api: some FileDraftAPI,
        shareID: String,
        request: CreateFileRequest,
        knownDraftLinkID: String?
    ) async throws -> (linkID: String, revisionID: String) {
        let parent = request.parentLinkID
        let probe = try await api.checkAvailableHashes(
            shareID: shareID, parentLinkID: parent, hashes: [request.hash]
        )
        let stale = ownStaleDrafts(
            pending: probe.pending, hash: request.hash,
            clientUID: request.clientUID, knownDraftLinkID: knownDraftLinkID
        )
        for linkID in stale {
            // Best effort here: if it fails, the create below answers 2500
            // and the second pass retries the delete (and surfaces it).
            try? await api.deleteDraft(shareID: shareID, parentLinkID: parent, linkID: linkID)
        }
        do {
            return try await api.createFileDraft(shareID: shareID, request: request)
        } catch where FolderConflictPolicy.isDuplicateName(error) {
            let again = try await api.checkAvailableHashes(
                shareID: shareID, parentLinkID: parent, hashes: [request.hash]
            )
            let ours = ownStaleDrafts(
                pending: again.pending, hash: request.hash,
                clientUID: request.clientUID, knownDraftLinkID: knownDraftLinkID
            )
            guard !ours.isEmpty else { throw error }
            for linkID in ours {
                try await api.deleteDraft(shareID: shareID, parentLinkID: parent, linkID: linkID)
            }
            return try await api.createFileDraft(shareID: shareID, request: request)
        }
    }
}
