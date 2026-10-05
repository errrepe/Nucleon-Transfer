// Nucleon Transfer — browser folder write ops (F7 S2.3).
// Thin @MainActor façade over DriveClient + NodeKeyResolver for the two
// folder-mutating browser actions: create and trash. Both publish the
// touched parent via TransferActivityStore.remoteChanged so the browser
// marks that folder stale and refetches — the targeted post-operation
// reload (no global refresh counter, no polling).
import Foundation

/// User-mappable failures specific to folder ops. LocalizedError, so
/// UserFacingError's generic path echoes the message verbatim.
enum FolderOperationError: LocalizedError, Sendable {
    /// Duplicate name in the parent — Proton API code 2500 (AlreadyExists /
    /// NodeWithSameNameExists per the official SDK: ProtonDriveApps/sdk,
    /// DriveApiResponseCodes.AlreadyExists → NodeWithSameNameExists).
    case duplicateName(String)
    /// Write ops unavailable — resolver not wired (signed out mid-flight).
    case sessionNotReady

    var errorDescription: String? {
        switch self {
        case let .duplicateName(name):
            return String(localized: "A folder named “\(name)” already exists.")
        case .sessionNotReady:
            return String(localized: "Session not ready. Sign in again.")
        }
    }
}

@MainActor
struct FolderOperations {
    let drive: DriveClient
    let resolver: NodeKeyResolver
    let addressKeys: [KeyringCache.UnlockedKey]
    let activity: TransferActivityStore

    /// Creates `name` under `parent`, returning the new folder's linkID.
    /// Same createFolder arguments as DriveUploadAdapter.ensureFolder
    /// (parent keyring + hash key + the share's signature identity), but
    /// without the merge-on-duplicate probe — a duplicate name surfaces as
    /// `FolderOperationError.duplicateName` instead of a silent merge.
    /// After the POST, the fresh folder resolves through the shared
    /// resolver (getLink → unlockNode → hash key, inside `folder(...)`) and
    /// is registered, so later downloads/ops hit the memo, not the network.
    func createFolder(name: String, in parent: DriveLocation) async throws -> String {
        let ctx = try await resolver.folder(
            shareID: parent.shareID, linkID: parent.linkID
        )
        let created: (linkID: String, node: FolderCreate.NodeMaterial)
        do {
            created = try await drive.createFolder(
                shareID: parent.shareID,
                parentLinkID: parent.linkID,
                name: name,
                parentKeys: ctx.keys,
                parentHashKey: ctx.hashKey,
                addressKeys: addressKeys,
                signatureAddress: ctx.signatureEmail,
                signatureEmail: ctx.signatureEmail
            )
        } catch let error as ProtonAPIError {
            throw Self.mapCreateError(error, name: name)
        }
        let folderCtx = try await resolver.folder(
            shareID: parent.shareID, linkID: created.linkID
        )
        await resolver.register(createdFolder: folderCtx)
        activity.remoteChanged(parentLinkIDs: [parent.linkID])
        return created.linkID
    }

    /// Moves `items` (children of `parent`) to Trash via the batch endpoint
    /// (POST …/trash_multiple; per-item API codes throw). The caller does
    /// the optimistic cache removal + reload.
    func trash(_ items: [DriveItem], in parent: DriveLocation) async throws {
        try await drive.trashChildren(
            shareID: parent.shareID,
            parentLinkID: parent.linkID,
            linkIDs: items.map(\.id)
        )
        activity.remoteChanged(parentLinkIDs: [parent.linkID])
    }

    /// Maps the createFolder error for UI. Duplicate detection lives in
    /// FolderConflictPolicy.isDuplicateName (single source of truth, shared
    /// with the upload adapter's merge probe — F7.1 R4).
    static func mapCreateError(_ error: ProtonAPIError, name: String) -> Error {
        if FolderConflictPolicy.isDuplicateName(error) {
            return FolderOperationError.duplicateName(name)
        }
        return error
    }
}
