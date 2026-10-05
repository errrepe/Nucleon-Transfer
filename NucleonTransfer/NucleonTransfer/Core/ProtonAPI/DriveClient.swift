// Nucleon Transfer — Drive read client (F3a: metadata only, no key unlock).
// Endpoints mirror rclone/go-proton-api + ProtonMail/go-proton-api:
//   GET /drive/volumes, /drive/shares[?ShowAll=1], /drive/shares/{id},
//   GET /drive/shares/{id}/links/{linkID},
//   GET /drive/shares/{id}/folders/{linkID}/children?Page=&PageSize=&ShowAll=
// 401 -> single SessionManager.refresh() + retry (mirrors go-proton-api doRes).
import Foundation

actor DriveClient {
    private let api: APIClient
    private let sessions: SessionManager
    /// Children page size — go-proton-api's `maxPageSize` (paging.go,
    /// const maxPageSize = 150), which its ListChildren sends as PageSize.
    private let pageSize = 150

    init(api: APIClient = APIClient(), sessions: SessionManager) {
        self.api = api
        self.sessions = sessions
    }

    func listVolumes() async throws -> [Volume] {
        try await authed { uid, token in
            try await api.get(VolumesResponse.self, path: "/drive/volumes", uid: uid, accessToken: token).volumes
        }
    }

    func listShares(showAll: Bool = true) async throws -> [ShareMetadata] {
        try await authed { uid, token in
            var query: [String: String]? = nil
            if showAll { query = ["ShowAll": "1"] }
            return try await api.get(SharesResponse.self, path: "/drive/shares", uid: uid, accessToken: token, query: query).shares
        }
    }

    func getShare(_ shareID: String) async throws -> DriveShare {
        // NOTE: go uses `struct { Share }` (embedded) so the response is FLAT
        // (all fields top-level), unlike the nested list endpoints.
        try await authed { uid, token in
            try await api.get(DriveShare.self, path: "/drive/shares/\(shareID)", uid: uid, accessToken: token)
        }
    }

    func getLink(shareID: String, linkID: String) async throws -> DriveLink {
        try await authed { uid, token in
            try await api.get(LinkResponse.self, path: "/drive/shares/\(shareID)/links/\(linkID)", uid: uid, accessToken: token).link
        }
    }

    /// All children across pages. F8.3-P3: stops on the first SHORT page
    /// (`count < pageSize`) instead of fetching a trailing empty page — a
    /// folder under `pageSize` children is now one round trip, not two.
    /// Upstream go-proton-api ListChildren (link_folder.go) still pages
    /// until an empty page; "a short page is the last page" is the
    /// assumption to confirm live (listed as a live check).
    func listChildren(shareID: String, linkID: String, showAll: Bool = false) async throws -> [DriveLink] {
        try await Self.collectPages(pageSize: pageSize) { page in
            try await self.authed { uid, token in
                try await self.api.get(
                    LinksResponse.self,
                    path: "/drive/shares/\(shareID)/folders/\(linkID)/children",
                    uid: uid,
                    accessToken: token,
                    query: [
                        "Page": String(page),
                        "PageSize": String(self.pageSize),
                        "ShowAll": showAll ? "1" : "0",
                    ]
                ).links
            }
        }
    }

    /// Page loop shared by paged listings: fetches page 0, 1, … and stops
    /// after the first page holding fewer than `pageSize` rows (an empty
    /// page included). Runs on the caller's executor.
    nonisolated(nonsending) static func collectPages<T>(
        pageSize: Int,
        fetch: (Int) async throws -> [T]
    ) async rethrows -> [T] {
        var all: [T] = []
        var page = 0
        while true {
            let batch = try await fetch(page)
            all.append(contentsOf: batch)
            if batch.count < pageSize { break }
            page += 1
        }
        return all
    }

    // MARK: - folder creation (F4.2)

    /// Creates a folder under `parentLinkID`: generates a fresh node keypair +
    /// passphrase client-side (FolderCreate, mirroring Proton clients),
    /// encrypts Name/NodePassphrase to the parent keyring, signs with the
    /// address key, and POSTs /drive/shares/{shareID}/folders. Returns the
    /// created LinkID plus the node material needed to read it back.
    /// - `parentKeys`: unlocked PARENT keyring (share keys for a root child).
    /// - `parentHashKey`: parent folder's 32-byte hash key for the name HMAC.
    /// - `addressKeys`: unlocked address keys (the #22 key signs).
    func createFolder(
        shareID: String,
        parentLinkID: String,
        name: String,
        parentKeys: [KeyringCache.UnlockedKey],
        parentHashKey: Data,
        addressKeys: [KeyringCache.UnlockedKey],
        signatureAddress: String? = nil,
        signatureEmail: String? = nil,
        signArmoredPassphrase: Bool = false,
        xAttrPlaintext: Data? = nil
    ) async throws -> (linkID: String, node: FolderCreate.NodeMaterial) {
        let (request, node) = try FolderCreate.buildRequest(
            name: name, parentLinkID: parentLinkID, parentKeys: parentKeys,
            parentHashKey: parentHashKey, addressKeys: addressKeys,
            signatureAddress: signatureAddress, signatureEmail: signatureEmail,
            signArmoredPassphrase: signArmoredPassphrase,
            xAttrPlaintext: xAttrPlaintext
        )
        let res: CreateFolderResponse = try await authed { uid, token in
            try await api.post(
                CreateFolderResponse.self, path: "/drive/shares/\(shareID)/folders",
                uid: uid, accessToken: token, body: request
            )
        }
        return (res.folder.id, node)
    }

    // MARK: - file upload (F4.3)

    /// Duplicate-name probe under `parentLinkID` (pre-draft, mirrors the
    /// reference order). `hashes` are NameHash hex strings.
    func checkAvailableHashes(
        shareID: String, parentLinkID: String, hashes: [String]
    ) async throws -> (available: [String], pending: [PendingHash]) {
        let res: CheckAvailableHashesResponse = try await authed { uid, token in
            try await api.post(
                CheckAvailableHashesResponse.self,
                path: "/drive/shares/\(shareID)/links/\(parentLinkID)/checkAvailableHashes",
                uid: uid, accessToken: token,
                body: CheckAvailableHashesRequest(hashes: hashes)
            )
        }
        return (res.availableHashes, res.pendingHashes)
    }

    /// Deletes a DRAFT file link (stale draft of a failed attempt):
    /// delete_multiple on its parent, skipping trash — the call
    /// henrybear327/Proton-API-Bridge `file_upload.go`
    /// `handleRevisionConflict` makes for a draft-only link
    /// (`c.DeleteChildren(ctx, shareID, link.ParentLinkID, linkID)`); the
    /// ProtonDriveApps/sdk `upload/apiService.ts` `deleteDraft` uses the
    /// v2-volume form of the same delete_multiple.
    func deleteDraft(shareID: String, parentLinkID: String, linkID: String) async throws {
        try await deleteChildren(shareID: shareID, parentLinkID: parentLinkID, linkIDs: [linkID])
    }

    /// Posts a prepared file draft. Returns the draft LinkID + RevisionID.
    func createFileDraft(
        shareID: String, request: CreateFileRequest
    ) async throws -> (linkID: String, revisionID: String) {
        let res: CreateFileResponse = try await authed { uid, token in
            try await api.post(
                CreateFileResponse.self, path: "/drive/shares/\(shareID)/files",
                uid: uid, accessToken: token, body: request
            )
        }
        return (res.file.id, res.file.revisionID)
    }

    /// Opens block uploads for one batch of a revision (F8.3-P2: called
    /// per batch as blocks get encoded — StreamingUpload). Each entry
    /// carries Index, Size (encrypted packet length), EncSignature and Hash
    /// (base64 SHA-256 of the ENCRYPTED packet).
    func requestBlockUploads(
        addressID: String, shareID: String, linkID: String,
        revisionID: String, entries: [BlockUploadEntry]
    ) async throws -> [StorageUploadLink] {
        let res: RequestBlockUploadsResponse = try await authed { uid, token in
            try await api.post(
                RequestBlockUploadsResponse.self, path: "/drive/blocks",
                uid: uid, accessToken: token,
                body: RequestBlockUploadsRequest(
                    addressID: addressID, shareID: shareID, linkID: linkID,
                    revisionID: revisionID, blockList: entries
                )
            )
        }
        return res.uploadLinks
    }

    /// Uploads one raw encrypted block packet to its BareURL (runtime
    /// storage host) with the link Token. Match links to blocks by Index.
    func uploadBlockBytes(bareURL: String, token: String, bytes: Data) async throws {
        let boundary = FileUpload.freshBoundary()
        let body = FileUpload.multipartBlockBody(boundary: boundary, blockBytes: bytes)
        try await authed { uid, accessToken in
            try await api.uploadRawBlock(
                bareURL: bareURL, token: token, uid: uid,
                accessToken: accessToken, body: body, boundary: boundary
            )
        }
    }

    /// Commits a revision: manifest signature + node-encrypted XAttr.
    /// Returns the echoed link id/state (partial — use getLink for full).
    func commitRevision(
        shareID: String, linkID: String, revisionID: String,
        request: CommitRevisionRequest
    ) async throws -> CommitRevisionResponse {
        let res: CommitRevisionResponse = try await authed { uid, token in
            try await api.put(
                CommitRevisionResponse.self,
                path: "/drive/shares/\(shareID)/files/\(linkID)/revisions/\(revisionID)",
                uid: uid, accessToken: token, body: request
            )
        }
        guard res.code == 1000 || res.code == 1001 else {
            throw ProtonAPIError.api(code: res.code, message: "commit failed")
        }
        return res
    }

    /// Single-file upload, STREAMED (F8.3-P2 — StreamingUpload): the
    /// source is read, encrypted and signed block by block OFF this actor
    /// (only the network calls hop onto it), so listings and downloads keep
    /// flowing during a large upload. Returns the created LinkID +
    /// RevisionID + node material (needed to read back).
    /// - `parentKeys`: unlocked PARENT keyring (share keys for a root child).
    /// - `parentHashKey`: parent folder's 32-byte hash key (name HMAC).
    /// - `addressKeys`: unlocked address keys (the #22 key signs).
    /// - `addressID`: uploader's address ID for the /drive/blocks session.
    /// - `blockSize`: plaintext chunk size (default 4 MiB); an empty source
    ///   takes the no-blocks path (draft + commit, manifest over zero hashes).
    /// - `clientUID`: the job's ClientUID, sent with the draft (F8.2-R3).
    /// - `knownDraftLinkID`: draft LinkID a previous attempt persisted —
    ///   deleted before the new draft is created (FileDraftFlow).
    /// - `onDraftCreated`: reports the new draft's LinkID/RevisionID so the
    ///   queue persists them before any block is sent.
    /// - `onCommitSending`: fired right before the commit request goes out
    ///   (the queue persists it: from then on a failure may hide a
    ///   committed revision).
    /// - `progress`: cumulative plaintext bytes after each uploaded block.
    /// Any failure before the commit deletes the draft (best effort) — the
    /// ProtonDriveApps/sdk upload manager's `deleteDraftNode` on failure. A
    /// failed commit is verified first (UploadCommitVerification — the
    /// SDK's `isRevisionUploaded`): committed → success; verifiably not
    /// committed → draft deleted; unknown → the draft is left for the next
    /// attempt's verification (it may be the user's committed file).
    /// Cleanup and verification run in DETACHED tasks: they must not
    /// inherit a cancelled (paused/removed) upload's cancellation, which
    /// would abort their requests.
    nonisolated func uploadFile(
        shareID: String,
        parentLinkID: String,
        fileName: String,
        source: some UploadBlockSource,
        mimeType: String? = nil,
        parentKeys: [KeyringCache.UnlockedKey],
        parentHashKey: Data,
        addressKeys: [KeyringCache.UnlockedKey],
        addressID: String,
        signatureAddress: String? = nil,
        signatureEmail: String? = nil,
        blockSize: Int = FileUpload.defaultBlockSize,
        modificationTime: Date = Date(),
        clientUID: String? = nil,
        knownDraftLinkID: String? = nil,
        onDraftCreated: (@Sendable (_ linkID: String, _ revisionID: String) async -> Void)? = nil,
        onCommitSending: (@Sendable () async -> Void)? = nil,
        progress: @Sendable (_ uploadedBytes: Int64) async -> Void = { _ in }
    ) async throws -> (linkID: String, revisionID: String, node: FolderCreate.NodeMaterial) {
        let done = try await StreamingUpload.run(
            api: self, shareID: shareID, parentLinkID: parentLinkID,
            fileName: fileName, source: source, mimeType: mimeType,
            parentKeys: parentKeys, parentHashKey: parentHashKey,
            addressKeys: addressKeys, addressID: addressID,
            signatureAddress: signatureAddress, signatureEmail: signatureEmail,
            blockSize: blockSize, modificationTime: modificationTime,
            clientUID: clientUID, knownDraftLinkID: knownDraftLinkID,
            onDraftCreated: onDraftCreated, onCommitSending: onCommitSending,
            progress: progress
        )
        return (done.linkID, done.revisionID, done.node)
    }

    /// In-memory convenience over `uploadFile(source:)` (live battery).
    nonisolated func uploadFile(
        shareID: String,
        parentLinkID: String,
        fileName: String,
        data: Data,
        mimeType: String? = nil,
        parentKeys: [KeyringCache.UnlockedKey],
        parentHashKey: Data,
        addressKeys: [KeyringCache.UnlockedKey],
        addressID: String,
        signatureAddress: String? = nil,
        signatureEmail: String? = nil,
        blockSize: Int = FileUpload.defaultBlockSize,
        modificationTime: Date = Date(),
        clientUID: String? = nil,
        knownDraftLinkID: String? = nil,
        onDraftCreated: (@Sendable (_ linkID: String, _ revisionID: String) async -> Void)? = nil,
        onCommitSending: (@Sendable () async -> Void)? = nil
    ) async throws -> (linkID: String, revisionID: String, node: FolderCreate.NodeMaterial) {
        try await uploadFile(
            shareID: shareID, parentLinkID: parentLinkID, fileName: fileName,
            source: DataBlockSource(data: data), mimeType: mimeType,
            parentKeys: parentKeys, parentHashKey: parentHashKey,
            addressKeys: addressKeys, addressID: addressID,
            signatureAddress: signatureAddress, signatureEmail: signatureEmail,
            blockSize: blockSize, modificationTime: modificationTime,
            clientUID: clientUID, knownDraftLinkID: knownDraftLinkID,
            onDraftCreated: onDraftCreated, onCommitSending: onCommitSending
        )
    }

    /// The SDK's `isRevisionUploaded` over GET link (UploadCommitVerification).
    func isRevisionCommitted(
        shareID: String, linkID: String, revisionID: String, parentLinkID: String?
    ) async throws -> Bool {
        let link = try await getLink(shareID: shareID, linkID: linkID)
        return UploadCommitVerification.isCommitted(link, revisionID: revisionID, parentLinkID: parentLinkID)
    }

    // MARK: - file download (F5)

    /// Lists a file's revisions (newest last in the capture; callers pick
    /// the active revision id from the link's FileProperties instead).
    func listRevisions(shareID: String, linkID: String) async throws -> [RevisionSummary] {
        try await authed { uid, token in
            try await api.get(
                RevisionsResponse.self,
                path: "/drive/shares/\(shareID)/files/\(linkID)/revisions",
                uid: uid, accessToken: token
            ).revisions
        }
    }

    /// Fetches one revision with its block list (Index/Hash/Token/URL/
    /// BareURL per block — the download session).
    func getRevision(
        shareID: String, linkID: String, revisionID: String
    ) async throws -> RevisionDetail {
        try await authed { uid, token in
            try await api.get(
                RevisionResponse.self,
                path: "/drive/shares/\(shareID)/files/\(linkID)/revisions/\(revisionID)",
                uid: uid, accessToken: token
            ).revision
        }
    }

    /// Downloads one raw encrypted block packet from its runtime storage
    /// host (BareURL + Token header; falls back to the full URL when the
    /// BareURL is empty). Returns the exact storage bytes (wire `Size`).
    func downloadBlockBytes(block: RevisionBlock) async throws -> Data {
        try await authed { uid, accessToken in
            if !block.bareURL.isEmpty, !block.token.isEmpty {
                return try await api.downloadRawBlock(
                    bareURL: block.bareURL, token: block.token,
                    uid: uid, accessToken: accessToken
                )
            }
            guard !block.url.isEmpty else {
                throw ProtonAPIError.transport(URLError(.badURL))
            }
            return try await api.downloadRawBlockURL(
                url: block.url, token: block.token,
                uid: uid, accessToken: accessToken
            )
        }
    }

    /// Trashes children (state -> trashed). Per-item API codes surface as errors.
    func trashChildren(shareID: String, parentLinkID: String, linkIDs: [String]) async throws {        let res: BatchChildrenResponse = try await authed { uid, token in
            try await api.post(
                BatchChildrenResponse.self,
                path: "/drive/shares/\(shareID)/folders/\(parentLinkID)/trash_multiple",
                uid: uid, accessToken: token, body: BatchChildrenRequest(linkIDs: linkIDs)
            )
        }
        for r in res.responses where r.response.code != 1000 && r.response.code != 1001 {
            throw ProtonAPIError.api(code: r.response.code, message: r.response.error ?? "trash failed")
        }
    }

    /// Permanently deletes (trashed) children. Per-item codes surface as errors.
    func deleteChildren(shareID: String, parentLinkID: String, linkIDs: [String]) async throws {
        let res: BatchChildrenResponse = try await authed { uid, token in
            try await api.post(
                BatchChildrenResponse.self,
                path: "/drive/shares/\(shareID)/folders/\(parentLinkID)/delete_multiple",
                uid: uid, accessToken: token, body: BatchChildrenRequest(linkIDs: linkIDs)
            )
        }
        for r in res.responses where r.response.code != 1000 && r.response.code != 1001 {
            throw ProtonAPIError.api(code: r.response.code, message: r.response.error ?? "delete failed")
        }
    }

    // MARK: - plumbing

    private func authed<T: Sendable>(_ op: @Sendable (String, String) async throws -> T) async throws -> T {
        try await sessions.withAuth(op)
    }
}

extension DriveClient: FileUploadAPI {}
