// Nucleon Transfer — streaming file upload pipeline (F8.3-P2, backlog B1).
// The F4.3 path read the whole file, encrypted + signed EVERY block up front
// (plaintext + ciphertext kept: ~3x the file in memory) and did it
// synchronously inside the DriveClient actor, so a 1 GB upload blocked every
// listing/download behind it; blocks went out one by one and progress
// jumped 0 -> total. Now:
//   1. draft material once (FileUpload.prepareDraft: node key, content
//      session key, signatures) -> FileDraftFlow.createDraft;
//   2. blocks in batches of `window`: each block is read from the source
//      (pread, 4 MiB), encrypted, hashed and signed in a child task on the
//      global executor (this function is @concurrent — never on an actor),
//      then ONE /drive/blocks request for the batch's upload links and the
//      batch's POSTs in parallel; the buffers are dropped before the next
//      batch. Only the block hashes (manifest), plaintext sizes (XAttr
//      BlockSizes) and a running SHA-1 of the plaintext (XAttr
//      Digests.SHA1, F8.3-P6) outlive a batch. Upstream batches the same way:
//      henrybear327/Proton-API-Bridge file_upload.go
//      `uploadAndCollectBlockData` — `RequestBlockUpload` per
//      UPLOAD_BATCH_BLOCK_SIZE (8) encrypted blocks, then the batch's
//      `UploadBlock`s in parallel (semaphore-bounded);
//   3. commit (manifest over the ordered block hashes + XAttr) with the
//      F8.2 lost-commit verification; any failure before the commit
//      discards the draft (detached, so a cancelled job still cleans up).
// Progress is reported per uploaded block (cumulative plaintext bytes,
// monotonic). Cancellation is checked between batches and before each POST.

import CryptoKit
import Foundation

// MARK: - block sources

/// Random-access plaintext for the pipeline (the job's file in the app).
protocol UploadBlockSource: Sendable {
    /// Total plaintext size, fixed when the source is opened.
    var size: Int64 { get }
    /// Exactly `count` bytes at `offset` (throws when fewer are available).
    func read(offset: Int64, count: Int) throws -> Data
}

enum UploadSourceError: Error, Sendable, Equatable {
    case cannotOpen(errno: Int32)
    case readFailed(errno: Int32)
    /// The file got shorter while it was being uploaded.
    case truncated
}

/// In-memory source (tests, the `data:` convenience).
struct DataBlockSource: UploadBlockSource {
    let data: Data
    var size: Int64 { Int64(data.count) }

    func read(offset: Int64, count: Int) throws -> Data {
        guard offset >= 0, count >= 0, offset + Int64(count) <= size else {
            throw UploadSourceError.truncated
        }
        let start = data.startIndex + Int(offset)
        return Data(data[start..<(start + count)])
    }
}

/// File source over one read-only descriptor: `pread` is positional and
/// thread-safe, so concurrent block reads need no shared cursor. The
/// descriptor closes when the last reference goes away.
final class FileBlockSource: UploadBlockSource {
    private let fd: Int32
    let size: Int64

    init(url: URL) throws {
        let fd = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_RDONLY | O_CLOEXEC)
        }
        guard fd >= 0 else { throw UploadSourceError.cannotOpen(errno: errno) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            let err = errno
            close(fd)
            throw UploadSourceError.cannotOpen(errno: err)
        }
        self.fd = fd
        self.size = Int64(st.st_size)
    }

    deinit { close(fd) }

    func read(offset: Int64, count: Int) throws -> Data {
        var out = Data(count: count)
        var done = 0
        try out.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while done < count {
                let n = pread(fd, base + done, count - done, off_t(offset) + off_t(done))
                if n < 0 {
                    if errno == EINTR { continue }
                    throw UploadSourceError.readFailed(errno: errno)
                }
                if n == 0 { throw UploadSourceError.truncated }
                done += n
            }
        }
        return out
    }
}

// MARK: - API surface

/// Everything the pipeline sends (DriveClient in the app, fakes in tests).
protocol FileUploadAPI: FileDraftAPI {
    /// /drive/blocks for one batch: upload links matched by `Index`.
    func requestBlockUploads(
        addressID: String, shareID: String, linkID: String,
        revisionID: String, entries: [BlockUploadEntry]
    ) async throws -> [StorageUploadLink]
    /// One storage POST of a raw encrypted block.
    func uploadBlockBytes(bareURL: String, token: String, bytes: Data) async throws
    func commitRevision(
        shareID: String, linkID: String, revisionID: String,
        request: CommitRevisionRequest
    ) async throws -> CommitRevisionResponse
    /// UploadCommitVerification's `isRevisionUploaded` lookup.
    func isRevisionCommitted(
        shareID: String, linkID: String, revisionID: String, parentLinkID: String?
    ) async throws -> Bool
}

// MARK: - pipeline

enum StreamingUpload {
    /// Blocks encoded + in flight per file (bounded memory: about
    /// `window` x 2 x blockSize while a batch is encoded/sent).
    static let defaultWindow = 4

    struct Result: Sendable {
        var linkID: String
        var revisionID: String
        var node: FolderCreate.NodeMaterial
    }

    static func blockCount(size: Int64, blockSize: Int) -> Int {
        guard size > 0 else { return 0 }
        let b = Int64(max(1, blockSize))
        return Int((size + b - 1) / b)
    }

    /// Full upload of `source` as a new file under `parentLinkID` (see the
    /// file header for the stages). Parameters as DriveClient.uploadFile.
    @concurrent
    static func run(
        api: some FileUploadAPI,
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
        window: Int = defaultWindow,
        modificationTime: Date = Date(),
        clientUID: String? = nil,
        knownDraftLinkID: String? = nil,
        node: FolderCreate.NodeMaterial? = nil,
        contentKey: Data? = nil,
        onDraftCreated: (@Sendable (_ linkID: String, _ revisionID: String) async -> Void)? = nil,
        onCommitSending: (@Sendable () async -> Void)? = nil,
        progress: @Sendable (_ uploadedBytes: Int64) async -> Void = { _ in }
    ) async throws -> Result {
        let size = source.size
        let blockSize = max(1, blockSize)
        let mime = try mimeType ?? FileUpload.mimeType(
            fileName: fileName,
            data: source.read(offset: 0, count: Int(min(512, size)))
        )
        var draft = try FileUpload.prepareDraft(
            fileName: fileName, parentLinkID: parentLinkID, mimeType: mime,
            parentKeys: parentKeys, parentHashKey: parentHashKey,
            addressKeys: addressKeys, signatureAddress: signatureAddress,
            signatureEmail: signatureEmail, node: node, contentKey: contentKey
        )
        draft.request.clientUID = clientUID
        try Task.checkCancellation()
        let ids = try await FileDraftFlow.createDraft(
            api: api, shareID: shareID, request: draft.request,
            knownDraftLinkID: knownDraftLinkID
        )
        await onDraftCreated?(ids.linkID, ids.revisionID)
        let commit: CommitRevisionRequest
        do {
            let manifest = try await uploadBlocks(
                api: api, source: source, draft: draft, ids: ids,
                shareID: shareID, addressID: addressID,
                blockSize: blockSize, window: max(1, window), progress: progress
            )
            let xattr = try FileUpload.xAttrJSON(
                modificationTime: modificationTime, size: size,
                mimeType: mime, blockSizes: manifest.plaintextSizes,
                sha1: manifest.sha1
            )
            commit = try FileUpload.buildCommit(
                manifestHashes: manifest.hashes, xAttrJSON: xattr,
                node: draft.node, addressKeys: addressKeys,
                signatureAddress: signatureAddress, signatureEmail: signatureEmail
            )
        } catch {
            await discardDraftDetached(api: api, shareID: shareID, parentLinkID: parentLinkID, linkID: ids.linkID)
            throw error
        }
        await onCommitSending?()
        let outcome = await UploadCommitVerification.commit(
            send: {
                _ = try await api.commitRevision(
                    shareID: shareID, linkID: ids.linkID,
                    revisionID: ids.revisionID, request: commit
                )
            },
            isCommitted: {
                try await Task.detached {
                    try await api.isRevisionCommitted(
                        shareID: shareID, linkID: ids.linkID,
                        revisionID: ids.revisionID, parentLinkID: parentLinkID
                    )
                }.value
            }
        )
        switch outcome {
        case .committed:
            return Result(linkID: ids.linkID, revisionID: ids.revisionID, node: draft.node)
        case let .notCommitted(error):
            await discardDraftDetached(api: api, shareID: shareID, parentLinkID: parentLinkID, linkID: ids.linkID)
            throw error
        case let .unknown(error):
            throw error
        }
    }

    /// What the commit needs from the blocks, in index order.
    struct Manifest: Sendable {
        var hashes: [Data]
        var plaintextSizes: [Int]
        /// Raw SHA-1 of the whole plaintext (XAttr Digests.SHA1).
        var sha1 = Data()
    }

    /// Batches of `window` blocks: encode in parallel (child tasks, global
    /// executor), one link request, parallel POSTs, then drop the buffers.
    /// The plaintext SHA-1 must see the bytes in file order: batches run in
    /// order, and within a batch each finished block's plaintext is parked
    /// only until every lower index is hashed (hashing overlaps the other
    /// encodes), then dropped — no more than the batch already holds.
    @concurrent
    static func uploadBlocks(
        api: some FileUploadAPI,
        source: some UploadBlockSource,
        draft: FileUpload.PreparedDraft,
        ids: (linkID: String, revisionID: String),
        shareID: String,
        addressID: String,
        blockSize: Int,
        window: Int,
        progress: @Sendable (Int64) async -> Void
    ) async throws -> Manifest {
        let size = source.size
        let count = blockCount(size: size, blockSize: blockSize)
        var manifest = Manifest(
            hashes: [Data](repeating: Data(), count: count),
            plaintextSizes: [Int](repeating: 0, count: count)
        )
        var sha1 = Insecure.SHA1()
        var uploaded: Int64 = 0
        var start = 0
        while start < count {
            try Task.checkCancellation()
            let end = min(start + window, count)
            let batch = try await withThrowingTaskGroup(
                of: (block: FileUpload.EncodedBlock, plaintext: Data).self
            ) { group in
                for i in start..<end {
                    group.addTask {
                        let offset = Int64(i) * Int64(blockSize)
                        let length = Int(min(Int64(blockSize), size - offset))
                        let plaintext = try source.read(offset: offset, count: length)
                        let block = try FileUpload.encodeBlock(index: i + 1, plaintext: plaintext, draft: draft)
                        return (block, plaintext)
                    }
                }
                var out: [FileUpload.EncodedBlock] = []
                out.reserveCapacity(end - start)
                var parked: [Int: Data] = [:] // 1-based index -> plaintext
                var nextToHash = start + 1
                for try await done in group {
                    out.append(done.block)
                    parked[done.block.index] = done.plaintext
                    while let plaintext = parked.removeValue(forKey: nextToHash) {
                        sha1.update(data: plaintext)
                        nextToHash += 1
                    }
                }
                return out.sorted { $0.index < $1.index }
            }
            try Task.checkCancellation()
            let links = try await api.requestBlockUploads(
                addressID: addressID, shareID: shareID, linkID: ids.linkID,
                revisionID: ids.revisionID, entries: batch.map(\.uploadEntry)
            )
            guard !links.isEmpty, links.count == batch.count else {
                throw FileUploadError.emptyUploadLinks
            }
            var targets: [(link: StorageUploadLink, block: FileUpload.EncodedBlock)] = []
            for block in batch {
                guard let link = links.first(where: { $0.index == block.index }) else {
                    throw FileUploadError.uploadLinkMismatch
                }
                targets.append((link, block))
            }
            try await withThrowingTaskGroup(of: Int.self) { group in
                for target in targets {
                    group.addTask {
                        try Task.checkCancellation()
                        try await api.uploadBlockBytes(
                            bareURL: target.link.bareURL, token: target.link.token,
                            bytes: target.block.encrypted
                        )
                        return target.block.plaintextSize
                    }
                }
                for try await sent in group {
                    uploaded += Int64(sent)
                    await progress(uploaded)
                }
            }
            for block in batch {
                manifest.hashes[block.index - 1] = block.hash
                manifest.plaintextSizes[block.index - 1] = block.plaintextSize
            }
            start = end
        }
        manifest.sha1 = Data(sha1.finalize())
        return manifest
    }

    /// Best-effort draft delete in a detached task (not cancelled with the
    /// upload); awaited so the caller's error surfaces after the cleanup.
    private static func discardDraftDetached(
        api: some FileUploadAPI, shareID: String, parentLinkID: String, linkID: String
    ) async {
        _ = await Task.detached {
            try? await api.deleteDraft(shareID: shareID, parentLinkID: parentLinkID, linkID: linkID)
        }.value
    }
}
