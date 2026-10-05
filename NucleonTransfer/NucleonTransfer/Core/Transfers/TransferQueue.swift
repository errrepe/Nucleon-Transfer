// Nucleon Transfer — upload queue core (F4.4; F8.3-P4 parallel tree folders).
// Offline-testable: Foundation only (no SwiftUI/SwiftData/DriveClient here).
// Live wiring lives in DriveUploadAdapter.swift; UI in Features/Transfers/.
//
// Persistence = plain JSON snapshot in Application Support (NOT SwiftData:
// a queue actor owning one Codable snapshot written atomically has fewer
// failure modes than a @Model graph + ModelContext threading — and the
// snapshot holds only paths/IDs/progress, NEVER secrets).

import Foundation

// MARK: - Job model

/// Upload job lifecycle: queued → uploading → done, with paused / failed /
/// cancelled as operator- or error-driven exits. `uploading` never survives
/// a relaunch (reset to `queued` on load — TRANSFERS.md §6).
enum TransferJobState: String, Codable, Sendable, Equatable {
    case queued
    case uploading
    case paused
    case done
    case failed
    case cancelled
}

/// One local file → one remote parent. Secrets-free by construction: only
/// filesystem paths, remote IDs, sizes and counters. Key material stays in
/// the KeyringCache/SessionManager actors (memory only).
struct TransferJob: Codable, Sendable, Identifiable, Equatable {
    var id: UUID
    var fileName: String
    /// Path relative to the drop root, e.g. "docs/a.txt" (NFC-normalized).
    var relativePath: String
    /// Absolute local path at enqueue time.
    var localPath: String
    /// Best-effort security-scoped bookmark (live only; nil in tests).
    var localBookmark: Data?
    var shareID: String
    /// Remote parent LinkID resolved at enqueue time (tree folders first).
    var parentLinkID: String
    var state: TransferJobState
    var bytesTotal: Int64
    var bytesDone: Int64
    /// Completed upload tries (persistent counter — TRANSFERS.md §3).
    var attempt: Int
    var maxAttempts: Int
    var errorMessage: String?
    /// Proton API code of the failure behind `errorMessage`, when the
    /// error carried one (F8.4-U1: 2000 = app not allowlisted for block
    /// upload). Kept typed so the UI never parses the message text.
    var errorCode: Int?
    var createdAt: Date
    var updatedAt: Date
    /// Remote LinkID after a successful upload.
    var remoteLinkID: String?
    /// Per-job ClientUID sent with the file draft (F8.2-R3): lets a retry
    /// recognise its own stale draft in checkAvailableHashes' PendingHashes.
    var clientUID: String?
    /// Draft LinkID/RevisionID of the attempt in progress (persisted as soon
    /// as the draft exists; cleared on success) — a relaunch deletes it.
    var draftLinkID: String?
    var draftRevisionID: String?
    /// The commit of that draft was sent (F8.2 review): a failure after
    /// this point may hide a revision the server DID commit (lost
    /// response), so the next attempt verifies before re-uploading and the
    /// draft is never blindly deleted.
    var draftCommitSent: Bool
    /// Proton user ID of the account that enqueued the job (F8.2-R7 / B12).
    /// The queue only shows and runs jobs of the signed-in account. nil =
    /// written before B12 (or enqueued while unscoped) — adopted by the
    /// next account that signs in (`TransferQueue.setAccountScope`).
    var accountID: String?

    enum CodingKeys: String, CodingKey {
        case id, fileName, relativePath, localPath, localBookmark, shareID,
             parentLinkID, state, bytesTotal, bytesDone, attempt, maxAttempts,
             errorMessage, errorCode, createdAt, updatedAt, remoteLinkID,
             clientUID, draftLinkID, draftRevisionID, draftCommitSent, accountID
    }

    /// Tolerant decode (F8.2-R2): only the identity/destination fields are
    /// required; everything else defaults, and an unknown state (written by
    /// a newer build) parks the job as `.paused` instead of dropping it.
    /// Fields added later MUST be decoded with `decodeIfPresent`.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        fileName = try c.decode(String.self, forKey: .fileName)
        localPath = try c.decode(String.self, forKey: .localPath)
        shareID = try c.decode(String.self, forKey: .shareID)
        parentLinkID = try c.decode(String.self, forKey: .parentLinkID)
        relativePath = try c.decodeIfPresent(String.self, forKey: .relativePath) ?? fileName
        localBookmark = try? c.decodeIfPresent(Data.self, forKey: .localBookmark)
        let rawState = try c.decodeIfPresent(String.self, forKey: .state)
        state = rawState.flatMap(TransferJobState.init(rawValue:)) ?? .paused
        bytesTotal = try c.decodeIfPresent(Int64.self, forKey: .bytesTotal) ?? 0
        bytesDone = try c.decodeIfPresent(Int64.self, forKey: .bytesDone) ?? 0
        attempt = try c.decodeIfPresent(Int.self, forKey: .attempt) ?? 0
        maxAttempts = try c.decodeIfPresent(Int.self, forKey: .maxAttempts) ?? 5
        errorMessage = try c.decodeIfPresent(String.self, forKey: .errorMessage)
        errorCode = try? c.decodeIfPresent(Int.self, forKey: .errorCode)
        createdAt = (try? c.decodeIfPresent(Date.self, forKey: .createdAt)) ?? Date()
        updatedAt = (try? c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
        remoteLinkID = try c.decodeIfPresent(String.self, forKey: .remoteLinkID)
        clientUID = try c.decodeIfPresent(String.self, forKey: .clientUID)
        draftLinkID = try c.decodeIfPresent(String.self, forKey: .draftLinkID)
        draftRevisionID = try c.decodeIfPresent(String.self, forKey: .draftRevisionID)
        draftCommitSent = (try? c.decodeIfPresent(Bool.self, forKey: .draftCommitSent)) ?? false
        accountID = try c.decodeIfPresent(String.self, forKey: .accountID)
    }

    var progress: Double {
        guard bytesTotal > 0 else { return state == .done ? 1 : 0 }
        return min(1, max(0, Double(bytesDone) / Double(bytesTotal)))
    }

    init(
        id: UUID = UUID(),
        fileName: String,
        relativePath: String,
        localPath: String,
        localBookmark: Data? = nil,
        shareID: String,
        parentLinkID: String,
        bytesTotal: Int64,
        maxAttempts: Int = 5,
        accountID: String? = nil
    ) {
        self.id = id
        self.fileName = fileName
        self.relativePath = relativePath
        self.localPath = localPath
        self.localBookmark = localBookmark
        self.shareID = shareID
        self.parentLinkID = parentLinkID
        state = .queued
        self.bytesTotal = bytesTotal
        bytesDone = 0
        attempt = 0
        self.maxAttempts = maxAttempts
        createdAt = Date()
        updatedAt = Date()
        clientUID = UUID().uuidString
        draftCommitSent = false
        self.accountID = accountID
    }
}

// MARK: - Account scope (F8.2-R7 / B12)

/// Which jobs the queue exposes and runs. The snapshot file is shared by
/// every account that signs in on this Mac; a job must never be shown to,
/// or uploaded with the keys of, another account.
enum TransferAccountScope: Sendable, Equatable {
    /// Every job (tests, previews — the pre-B12 behaviour).
    case all
    /// Only jobs stamped with this Proton user ID.
    case account(String)
    /// Nobody signed in: nothing is visible, nothing runs.
    case signedOut

    func includes(_ job: TransferJob) -> Bool {
        switch self {
        case .all: return true
        case let .account(id): return job.accountID == id
        case .signedOut: return false
        }
    }
}

// MARK: - Failure classification

/// Queue-level failure taxonomy. The live adapter maps transport/API errors
/// into this via `classify(_:)`; tests construct it directly.
enum TransferFailure: Error, Sendable, Equatable {
    /// Timeout, 429, 5xx — retry with backoff (TRANSFERS.md §3).
    case transient(String)
    /// 400/401/403/404/422, validation — fail immediately, surface to UI.
    case permanent(String)
    /// Proton HV 9001 — pause the whole queue, resume manually.
    case needsHumanVerification
    /// The upload was cancelled (Task cancellation, `URLError.cancelled`,
    /// possibly wrapped in `ProtonAPIError.transport`). Never a failure:
    /// whoever cancelled (pause / cancel / remove / sign-out) already set
    /// the job's state (F8.2-R1).
    case cancelled
}

enum TransferErrorClassify {
    /// Maps arbitrary errors to queue policy. Unknown errors are permanent:
    /// retry loops must be opt-in (transient), never the default.
    static func classify(_ error: Error) -> TransferFailure {
        if let f = error as? TransferFailure { return f }
        if isCancellation(error) { return .cancelled }
        if let api = error as? ProtonAPIError {
            switch api {
            case .humanVerificationRequired:
                return .needsHumanVerification
            case let .transport(underlying):
                return classify(underlying)
            case let .api(code, message):
                if code == 429 || (500...599).contains(code) {
                    return .transient("api \(code): \(message)")
                }
                return .permanent("api \(code): \(message)")
            case let .http(status, _, message, _):
                // F8.2-R3: classify on the HTTP status (storage + API).
                if APIClient.isRetryableStatus(status) {
                    return .transient("http \(status): \(message)")
                }
                return .permanent("http \(status): \(message)")
            case .rateLimited:
                // Login-rate-limit shape reused defensively: surface, don't spin.
                return .permanent("rate limited")
            default:
                // Persist a language-neutral, name-free token; the copy is
                // localized at display time (UserFacingError.message(forJob:)).
                return .permanent(UserFacingError.token(for: api))
            }
        }
        let ns = error as NSError
        if ns.domain == (NSURLErrorDomain as String) {
            switch ns.code {
            case NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost,
                 NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost,
                 NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed,
                 NSURLErrorResourceUnavailable, NSURLErrorInternationalRoamingOff,
                 NSURLErrorCallIsActive, NSURLErrorDataNotAllowed:
                return .transient(UserFacingError.token(for: error))
            default:
                return .permanent(UserFacingError.token(for: error))
            }
        }
        // F8.4-U2: never persist a raw localizedDescription — Cocoa file
        // errors quote file names, which the string mapper must not see.
        // F8.4 review: nor localized copy — a token, localized on display.
        return .permanent(UserFacingError.token(for: error))
    }

    /// The Proton envelope code carried by `error` (`.api` or an `.http`
    /// answer whose body had one), looking through `.transport` wrapping.
    /// nil for transport/local errors (F8.4-U1).
    static func protonCode(_ error: Error) -> Int? {
        guard let api = error as? ProtonAPIError else { return nil }
        switch api {
        case let .api(code, _): return code
        case let .http(_, code, _, _): return code
        case let .transport(underlying): return protonCode(underlying)
        default: return nil
        }
    }

    /// Server-requested wait (`Retry-After`, seconds) carried by `error`,
    /// looking through `ProtonAPIError.transport` wrapping.
    static func retryAfter(_ error: Error) -> TimeInterval? {
        guard let api = error as? ProtonAPIError else { return nil }
        switch api {
        case let .http(_, _, _, retryAfter): return retryAfter
        case let .transport(underlying): return self.retryAfter(underlying)
        default: return nil
        }
    }

    /// True for every shape a cancelled upload surfaces as: Swift
    /// `CancellationError`, `URLError(.cancelled)` / NSURLErrorCancelled,
    /// and either of those wrapped in `ProtonAPIError.transport`
    /// (APIClient.data(for:) wraps every URLSession error).
    static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let f = error as? TransferFailure { return f == .cancelled }
        if let api = error as? ProtonAPIError {
            if case let .transport(underlying) = api { return isCancellation(underlying) }
            return false
        }
        let ns = error as NSError
        return ns.domain == (NSURLErrorDomain as String) && ns.code == NSURLErrorCancelled
    }
}

// MARK: - Retry policy (pure)

/// Backoff per TRANSFERS.md §3: delay = min(cap, base * 2^(n-1)) + jitter,
/// base 1s, cap 60s, jitter 0..1s. `failures` = consecutive failed tries (≥1).
enum TransferRetryPolicy: Sendable {
    static let baseNanoseconds: UInt64 = 1_000_000_000
    static let capNanoseconds: UInt64 = 60_000_000_000
    static let maxJitterNanoseconds: UInt64 = 1_000_000_000

    /// Longest server-requested wait honoured (a hostile/buggy header must
    /// not park a slot for hours); 5 minutes.
    static let retryAfterCapNanoseconds: UInt64 = 300_000_000_000

    /// `retryAfter` (seconds, from the server's `Retry-After`) raises the
    /// delay to at least that long (capped at `retryAfterCapNanoseconds`),
    /// jitter still added on top so parallel jobs don't stampede.
    static func delayNanoseconds(failures: Int, jitter: UInt64 = 0, retryAfter: TimeInterval? = nil) -> UInt64 {
        let n = max(1, failures)
        // 2^(n-1), saturated before the shift can overflow.
        let shift = min(n - 1, 10)
        let exponential = baseNanoseconds << shift
        var base = min(capNanoseconds, exponential)
        if let retryAfter, retryAfter > 0 {
            let requested = min(Double(retryAfterCapNanoseconds), retryAfter * 1_000_000_000)
            base = max(base, UInt64(requested))
        }
        return base + min(jitter, maxJitterNanoseconds)
    }

    static func randomJitter() -> UInt64 {
        UInt64.random(in: 0...maxJitterNanoseconds)
    }
}

// MARK: - Uploader / folder-creator seams (mocked in tests)

/// Uploads one job's bytes. Reports cumulative bytesDone (0...bytesTotal);
/// returns the created remote LinkID. Throws TransferFailure (or anything —
/// the queue classifies via TransferErrorClassify).
protocol TransferUploader: Sendable {
    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void
    ) async throws -> String?

    /// Same, plus side-channel events the queue persists (draft IDs,
    /// refreshed bookmark). Defaults to the two-argument form.
    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void,
        events: TransferUploadEvents
    ) async throws -> String?

    /// Best-effort removal of the remote draft a cancelled/removed job left
    /// behind (`job.draftLinkID`, F8.2 review). Called from a detached,
    /// non-cancelled task. Must never delete a revision the server already
    /// committed (`job.draftCommitSent`). Throws when the draft may still
    /// exist. Default: nothing to clean up (offline fakes).
    func discardDraft(job: TransferJob) async throws
}

extension TransferUploader {
    func discardDraft(job: TransferJob) async throws {}

    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void,
        events: TransferUploadEvents
    ) async throws -> String? {
        try await upload(job: job, progress: progress)
    }
}

/// Callbacks an uploader fires mid-job so the queue can persist state that
/// must survive a crash/relaunch.
struct TransferUploadEvents: Sendable {
    /// The remote draft exists (F8.2-R3): LinkID + RevisionID.
    var draftCreated: @Sendable (_ linkID: String, _ revisionID: String) async -> Void
    /// The job's bookmark was stale and has been re-created (F8.2-R4).
    var bookmarkRefreshed: @Sendable (_ bookmark: Data) async -> Void
    /// The draft's commit request is about to be sent (F8.2 review): from
    /// here on a failure may hide a committed revision.
    var commitSending: @Sendable () async -> Void

    init(
        draftCreated: @escaping @Sendable (_ linkID: String, _ revisionID: String) async -> Void = { _, _ in },
        bookmarkRefreshed: @escaping @Sendable (_ bookmark: Data) async -> Void = { _ in },
        commitSending: @escaping @Sendable () async -> Void = {}
    ) {
        self.draftCreated = draftCreated
        self.bookmarkRefreshed = bookmarkRefreshed
        self.commitSending = commitSending
    }
}

/// Creates (or returns the existing) remote folder under a parent.
/// Returns the folder's LinkID. Name-conflict handling (merge into an
/// existing folder — FolderConflictPolicy) is the adapter's job; the
/// planner just calls in parent→child order.
protocol RemoteFolderCreator: Sendable {
    func ensureFolder(name: String, parentLinkID: String, shareID: String) async throws -> String
}

// MARK: - Queue

/// Bounded-concurrency upload scheduler + JSON persistence.
///
/// - Concurrency: at most `maxConcurrentUploads` jobs in flight (default 3;
///   each job uploads sequentially — DriveClient.uploadFile's verified path —
///   so per-job block parallelism stays deferred, TRANSFERS.md §1.5).
/// - Scheduling: FIFO of queued ids (F8.2-R2) — a completion pops the next
///   id instead of scanning every job.
/// - Retry: transient errors back off in-slot (the slot is held during the
///   sleep); pause/cancel win over a pending retry.
/// - Persistence (F8.2-R2): coalesced. Progress marks the snapshot dirty and
///   a trailing save runs within `saveDebounceNanoseconds` (~500 ms); state
///   transitions save at once unless a save already ran inside that window
///   (then the trailing save covers them). `flush()` writes synchronously
///   (app quit). Listener snapshots are coalesced the same way (~100 ms).
/// - Backoff sleeping is injectable (`sleeper`) so tests never wait.
/// - No uploader set (pre-login) → jobs accumulate `queued`; `start()` pumps.
actor TransferQueue {
    private var jobs: [UUID: TransferJob] = [:]
    /// Insertion order (stable UI listing).
    private var order: [UUID] = []
    /// Ids waiting for a slot, oldest first. Entries go stale when a job
    /// is paused/cancelled/removed — `pump` skips them lazily; an id can
    /// appear twice (resume of a still-listed job) and is started once.
    private var fifo: [UUID] = []
    private var fifoHead = 0
    /// Live runs: job ID → generation token of the ONE run that owns the
    /// slot. A run keeps its slot until its task actually returns — even
    /// after pause/cancel/remove cancelled it (the uploader may take a
    /// while to notice) — so concurrency never exceeds the limit and an id
    /// is never re-pumped while its previous run is still unwinding
    /// (F8.2-R1). `inFlight.count` is the number of occupied slots.
    private var inFlight: [UUID: UInt64] = [:]
    private var tasks: [UUID: Task<Void, Never>] = [:]
    private var nextGeneration: UInt64 = 0
    /// Removed jobs whose run is still unwinding: the run may still record
    /// a draft, which is discarded when it returns (F8.2 review).
    private var removedInFlight: [UUID: TransferJob] = [:]
    /// Detached draft-cleanup tasks (F8.2 review), keyed by a token so a
    /// finished one drops itself.
    private var cleanups: [UInt64: Task<Void, Never>] = [:]
    private var nextCleanup: UInt64 = 0
    private var uploader: (any TransferUploader)?
    private let store: (any TransferQueueStore)?
    /// Jobs outside the scope are hidden from `snapshot`/the listener and
    /// never pumped; their state is left untouched so they continue when
    /// their own account signs in again (F8.2-R7 / B12).
    private(set) var accountScope: TransferAccountScope
    /// UI hook: receives full snapshots (coalesced to ~100 ms).
    var listener: (@Sendable ([TransferJob]) -> Void)?

    var maxConcurrentUploads: Int
    /// Backoff wait; default = real Task.sleep (cancellable).
    var sleeper: @Sendable (UInt64) async -> Void = { ns in
        try? await Task.sleep(nanoseconds: ns)
    }

    // Coalesced persistence / notification.
    var saveDebounceNanoseconds: UInt64 = 500_000_000
    var notifyIntervalNanoseconds: UInt64 = 100_000_000
    /// Clock for the coalescing windows (injectable for tests).
    var now: @Sendable () -> Date = { Date() }
    private var dirty = false
    private var saveScheduled = false
    private var lastSave = Date.distantPast
    private var notifyScheduled = false
    private var lastNotify = Date.distantPast
    /// True when the loaded snapshot was lossy: the next write first copies
    /// the original file to `.bak`.
    private var needsBackup = false
    /// Snapshot writes performed (diagnostics + tests).
    private(set) var saveCount = 0

    init(
        storeURL: URL? = nil,
        uploader: (any TransferUploader)? = nil,
        maxConcurrentUploads: Int = 3,
        accountScope: TransferAccountScope = .all
    ) {
        self.init(
            store: storeURL.map { FileTransferQueueStore(url: $0) as any TransferQueueStore },
            uploader: uploader,
            maxConcurrentUploads: maxConcurrentUploads,
            accountScope: accountScope
        )
    }

    init(
        store: (any TransferQueueStore)?,
        uploader: (any TransferUploader)? = nil,
        maxConcurrentUploads: Int = 3,
        accountScope: TransferAccountScope = .all
    ) {
        self.store = store
        self.uploader = uploader
        self.maxConcurrentUploads = maxConcurrentUploads
        self.accountScope = accountScope
        guard let data = store?.read() else { return }
        let decoded = TransferQueueSnapshot.decode(data)
        needsBackup = decoded.lossy
        for var job in decoded.jobs where jobs[job.id] == nil {
            if job.state == .uploading { job.state = .queued } // resume after relaunch
            job.updatedAt = Date()
            jobs[job.id] = job
            order.append(job.id)
            if job.state == .queued { fifo.append(job.id) }
        }
    }

    /// Default snapshot location: Application Support/NucleonTransfer/.
    /// (Renamed in RN1 — the pre-rename snapshot under the legacy app dir is
    /// abandoned, not migrated: queue resume is best-effort at alpha stage.)
    static func defaultStoreURL() -> URL? {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        return base?.appendingPathComponent("NucleonTransfer/transfer-queue.json", isDirectory: false)
    }

    // MARK: configuration

    func setUploader(_ u: (any TransferUploader)?) {
        uploader = u
    }

    /// Test seam: synchronous backoff wait in tests (never sleeps for real).
    func setSleeper(_ s: @escaping @Sendable (UInt64) async -> Void) {
        sleeper = s
    }

    /// Test seam: coalescing windows + clock.
    func setCoalescing(
        saveDebounceNanoseconds: UInt64? = nil,
        notifyIntervalNanoseconds: UInt64? = nil,
        now: (@Sendable () -> Date)? = nil
    ) {
        if let saveDebounceNanoseconds { self.saveDebounceNanoseconds = saveDebounceNanoseconds }
        if let notifyIntervalNanoseconds { self.notifyIntervalNanoseconds = notifyIntervalNanoseconds }
        if let now { self.now = now }
    }

    func setMaxConcurrent(_ n: Int) {
        maxConcurrentUploads = n
        pump()
    }

    func setListener(_ l: (@Sendable ([TransferJob]) -> Void)?) {
        listener = l
    }

    /// Switches the visible/runnable account (F8.2-R7 / B12). Signing in
    /// passes `.account(userID)`, signing out `.signedOut`.
    ///
    /// Legacy adoption: jobs with no `accountID` (persisted before B12)
    /// are stamped with the FIRST account that becomes active — the old
    /// snapshot recorded no owner, and pre-B12 builds were used with one
    /// account per Mac in practice. Adopted jobs keep their state.
    ///
    /// The account's queued jobs go back in line (the pump skipped them
    /// while another account was active), then the queue pumps.
    func setAccountScope(_ scope: TransferAccountScope) {
        accountScope = scope
        if case let .account(id) = scope {
            var adopted = false
            for jobID in order where jobs[jobID]?.accountID == nil {
                jobs[jobID]?.accountID = id
                adopted = true
            }
            if adopted { persist(urgent: true) }
        }
        for jobID in order where isVisible(jobID) && jobs[jobID]?.state == .queued && inFlight[jobID] == nil {
            fifo.append(jobID)
        }
        publish()
        pump()
    }

    /// True when `id` exists and belongs to the active scope.
    private func isVisible(_ id: UUID) -> Bool {
        guard let job = jobs[id] else { return false }
        return accountScope.includes(job)
    }

    // MARK: enqueue

    func enqueue(_ job: TransferJob) {
        enqueueMany([job])
    }

    /// Adds jobs in one batch: one snapshot write + one notification for
    /// the whole batch (F8.2-R2 — per-file saves made big drops quadratic).
    func enqueueMany(_ newJobs: [TransferJob]) {
        guard !newJobs.isEmpty else { return }
        let stamp = Date()
        var owner: String?
        if case let .account(id) = accountScope { owner = id }
        for var j in newJobs {
            j.updatedAt = stamp
            if j.accountID == nil { j.accountID = owner } // B12: stamp the enqueuing account
            if jobs[j.id] == nil { order.append(j.id) }
            jobs[j.id] = j
            if j.state == .queued { fifo.append(j.id) }
        }
        persist(urgent: true)
        publish()
        pump()
    }

    /// Uploads a scanned local tree: creates remote folders parent→child
    /// (memoized per relative path), then enqueues one job per file with the
    /// resolved parent LinkID — all files in ONE `enqueueMany`. Entry
    /// bookmarks (created during the detached scan) travel into the jobs.
    /// `rootParentLinkID` is the existing remote folder the tree lands in;
    /// the entry with relativePath "" (the scan root itself) is never
    /// created — callers that want the dropped folder preserved pass
    /// entries rooted at its name (`LocalTreeScan.rooted`, F8.2-R6).
    ///
    /// F8.3-P4: folders are created level by level (all depth-1, then
    /// depth-2, …) and in parallel within a level, at most
    /// `folderConcurrency` at once — every parent exists before its level
    /// starts. The path→LinkID map is a local built once per level from the
    /// collected results, so actor state is only touched by the final
    /// `enqueueMany`. Any failure aborts the whole enqueue (nothing is
    /// queued), like the sequential loop did.
    /// - Returns: enqueued job IDs, in file-entry order.
    @discardableResult
    func enqueueTree(
        entries: [LocalTreeScan.Entry],
        shareID: String,
        rootParentLinkID: String,
        folders: any RemoteFolderCreator,
        maxAttempts: Int = 5,
        folderConcurrency: Int = 4
    ) async throws -> [UUID] {
        let remoteByRelPath = try await Self.createFolders(
            entries: entries, shareID: shareID, rootParentLinkID: rootParentLinkID,
            folders: folders, width: folderConcurrency
        )
        var batch: [TransferJob] = []
        for file in entries where !file.isDirectory {
            let parentRel = (file.relativePath as NSString).deletingLastPathComponent
            let parent = remoteByRelPath[parentRel] ?? rootParentLinkID
            let name = (file.relativePath as NSString).lastPathComponent
            batch.append(TransferJob(
                fileName: name,
                relativePath: file.relativePath,
                localPath: file.url.path,
                localBookmark: file.bookmark,
                shareID: shareID,
                parentLinkID: parent,
                bytesTotal: file.size,
                maxAttempts: maxAttempts
            ))
        }
        enqueueMany(batch)
        return batch.map(\.id)
    }

    /// One folder to create within a level.
    private struct FolderRequest: Sendable {
        var name: String
        var parentLinkID: String
    }

    /// Creates the tree's folders level by level (F8.3-P4) and returns the
    /// relative path → LinkID map ("" → `rootParentLinkID`). Static and
    /// nonisolated: it only reads its arguments, so the actor is free while
    /// folders are created and no actor state can change under it.
    ///
    /// Within a level, directories that resolve to the same (parent, NFC
    /// name) share ONE ensureFolder call — two concurrent creates of one
    /// name would race the merge policy; sequentially the second merged.
    /// A directory whose parent is missing from `entries` lands under
    /// `rootParentLinkID` (unchanged).
    private nonisolated static func createFolders(
        entries: [LocalTreeScan.Entry],
        shareID: String,
        rootParentLinkID: String,
        folders: any RemoteFolderCreator,
        width: Int
    ) async throws -> [String: String] {
        var remoteByRelPath = ["": rootParentLinkID]
        func depth(_ rel: String) -> Int {
            rel.isEmpty ? 0 : rel.utf8.reduce(1) { $1 == UInt8(ascii: "/") ? $0 + 1 : $0 }
        }
        var levels: [Int: [String]] = [:]
        for dir in entries where dir.isDirectory && !dir.relativePath.isEmpty {
            levels[depth(dir.relativePath), default: []].append(dir.relativePath)
        }
        for level in levels.keys.sorted() {
            // Unique paths, sorted: request order (and so the error picked
            // on failure) is deterministic.
            let rels = Set(levels[level] ?? []).sorted()
            var requests: [FolderRequest] = []
            var requestIndex: [String: Int] = [:] // "parent\0name" → requests index
            var relToRequest: [(rel: String, index: Int)] = []
            for rel in rels {
                let parentRel = (rel as NSString).deletingLastPathComponent
                let parent = remoteByRelPath[parentRel] ?? rootParentLinkID
                let name = ((rel as NSString).lastPathComponent as String)
                    .precomposedStringWithCanonicalMapping
                let key = parent + "\u{0}" + name
                let index: Int
                if let existing = requestIndex[key] {
                    index = existing
                } else {
                    index = requests.count
                    requestIndex[key] = index
                    requests.append(FolderRequest(name: name, parentLinkID: parent))
                }
                relToRequest.append((rel, index))
            }
            let linkIDs = try await ensureLevel(
                requests, shareID: shareID, folders: folders, width: width
            )
            for (rel, index) in relToRequest {
                remoteByRelPath[rel] = linkIDs[index]
            }
        }
        return remoteByRelPath
    }

    /// Runs one level's ensureFolder calls with at most `width` in flight.
    /// Returns LinkIDs aligned with `requests`. On failure the remaining
    /// requests are not started, in-flight ones are cancelled and awaited,
    /// and the error of the lowest-indexed failed request is thrown
    /// (cancellations it caused rank last) — deterministic regardless of
    /// completion order.
    private nonisolated static func ensureLevel(
        _ requests: [FolderRequest],
        shareID: String,
        folders: any RemoteFolderCreator,
        width: Int
    ) async throws -> [String] {
        var results = [String?](repeating: nil, count: requests.count)
        var failures: [(index: Int, error: any Error)] = []
        await withTaskGroup(of: (Int, Result<String, any Error>).self) { group in
            var next = 0
            func launch() {
                let index = next
                let request = requests[index]
                next += 1
                group.addTask {
                    do {
                        let id = try await folders.ensureFolder(
                            name: request.name, parentLinkID: request.parentLinkID, shareID: shareID
                        )
                        return (index, .success(id))
                    } catch {
                        return (index, .failure(error))
                    }
                }
            }
            while next < min(max(width, 1), requests.count) { launch() }
            while let (index, result) = await group.next() {
                switch result {
                case let .success(id):
                    results[index] = id
                    if failures.isEmpty, next < requests.count { launch() }
                case let .failure(error):
                    if failures.isEmpty { group.cancelAll() }
                    failures.append((index, error))
                }
            }
        }
        if !failures.isEmpty {
            let ranked = failures.sorted {
                let c0 = TransferErrorClassify.isCancellation($0.error)
                let c1 = TransferErrorClassify.isCancellation($1.error)
                if c0 != c1 { return !c0 }
                return $0.index < $1.index
            }
            throw ranked[0].error
        }
        return try results.map { id in
            guard let id else { throw CancellationError() }
            return id
        }
    }

    // MARK: operators

    /// Jobs of the active account scope, in insertion order (UI listing).
    func snapshot() -> [TransferJob] {
        order.compactMap { jobs[$0] }.filter(accountScope.includes)
    }

    /// Every persisted job, all accounts (diagnostics + tests).
    func allJobs() -> [TransferJob] {
        order.compactMap { jobs[$0] }
    }

    /// Any job by id, regardless of scope (tests, internal lookups).
    func job(id: UUID) -> TransferJob? { jobs[id] }

    /// Attaches (or refreshes) a job's security-scoped bookmark.
    func setBookmark(id: UUID, _ bookmark: Data?) {
        guard var j = jobs[id] else { return }
        j.localBookmark = bookmark
        jobs[id] = j
        persist()
    }

    /// Pumps queued jobs into free slots. No-op pre-login (no uploader).
    func start() { pump() }

    func pause(id: UUID) {
        guard isVisible(id), var j = jobs[id] else { return }
        switch j.state {
        case .queued, .uploading:
            j.state = .paused
            j.updatedAt = Date()
            jobs[id] = j
            tasks[id]?.cancel()
            persist(urgent: true)
            publish()
        case .paused, .done, .failed, .cancelled:
            break
        }
    }

    /// Pauses the active scope's queued/running jobs (other accounts'
    /// jobs never run, so there is nothing of theirs to stop).
    func pauseAll() {
        var touched = false
        for id in order where isVisible(id) {
            guard var j = jobs[id] else { continue }
            if j.state == .queued || j.state == .uploading {
                j.state = .paused
                j.updatedAt = Date()
                jobs[id] = j
                tasks[id]?.cancel()
                touched = true
            }
        }
        if touched {
            persist(urgent: true)
            publish()
        }
    }

    /// Sign-out (F8.2 review / B12): stops the active scope's uploads
    /// WITHOUT parking them as user-paused, so they continue when the same
    /// account signs back in. The uploader is detached first (no run can
    /// be pumped with the leaving account's keys), running jobs go back to
    /// `.queued` and their tasks are cancelled. A cancelled run then finds
    /// its job no longer `.uploading` and returns without touching it —
    /// the same state guard that protects pause/cancel (`run`), so the
    /// `.cancelled` branch (which parks as `.paused`) is never reached for
    /// a suspended job. A run that still completes records `.done`.
    /// Callers then switch the scope (`setAccountScope(.signedOut)`).
    func suspendForSignOut() {
        uploader = nil
        var touched = false
        for id in order where isVisible(id) {
            guard var j = jobs[id], j.state == .uploading else { continue }
            j.state = .queued
            j.updatedAt = Date()
            jobs[id] = j
            tasks[id]?.cancel()
            touched = true
        }
        if touched {
            persist(urgent: true)
            publish()
        }
    }

    func resume(id: UUID) {
        guard isVisible(id), var j = jobs[id], j.state == .paused else { return }
        j.state = .queued
        j.errorMessage = nil
        j.errorCode = nil
        j.updatedAt = Date()
        jobs[id] = j
        fifo.append(id)
        persist(urgent: true)
        publish()
        pump()
    }

    func cancel(id: UUID) {
        guard isVisible(id), var j = jobs[id] else { return }
        switch j.state {
        case .queued, .uploading, .paused, .failed:
            j.state = .cancelled
            j.updatedAt = Date()
            jobs[id] = j
            if inFlight[id] != nil {
                // The run's exit discards whatever draft it ends up with.
                tasks[id]?.cancel()
            } else {
                scheduleDiscard(j, using: uploader)
            }
            persist(urgent: true)
            publish()
        case .done, .cancelled:
            break
        }
    }

    /// Relaunch: failed/cancelled → fresh queued job (attempt + progress reset;
    /// F4.4 retries whole files — no partial-block resume yet, see docs).
    func relaunch(id: UUID) {
        guard isVisible(id), var j = jobs[id] else { return }
        guard j.state == .failed || j.state == .cancelled else { return }
        Self.resetForRelaunch(&j)
        jobs[id] = j
        fifo.append(id)
        persist(urgent: true)
        publish()
        pump()
    }

    /// Relaunches every FAILED job (UI "retry all"). User-cancelled jobs
    /// are left alone — only an explicit per-row relaunch restarts them.
    func relaunchAllFailed() {
        var touched = false
        for id in order where isVisible(id) {
            guard var j = jobs[id], j.state == .failed else { continue }
            Self.resetForRelaunch(&j)
            jobs[id] = j
            fifo.append(id)
            touched = true
        }
        if touched {
            persist(urgent: true)
            publish()
            pump()
        }
    }

    private static func resetForRelaunch(_ j: inout TransferJob) {
        j.state = .queued
        j.attempt = 0
        j.bytesDone = 0
        j.errorMessage = nil
        j.errorCode = nil
        j.remoteLinkID = nil
        j.updatedAt = Date()
    }

    /// Drops the job. A running upload is cancelled but keeps its slot
    /// (`inFlight`) until its task really returns — releasing it here let
    /// the pump start another upload while this one was still unwinding,
    /// exceeding the concurrency limit (F8.2-R1).
    /// Its server draft (if any) is discarded best-effort — at once when
    /// idle, else when the unwinding run returns (F8.2 review).
    func remove(id: UUID) {
        guard isVisible(id), let removed = jobs[id] else { return }
        if inFlight[id] != nil {
            removedInFlight[id] = removed
            tasks[id]?.cancel()
        } else {
            scheduleDiscard(removed, using: uploader)
        }
        jobs[id] = nil
        order.removeAll { $0 == id }
        persist(urgent: true)
        publish()
        pump()
    }

    func reportProgress(id: UUID, bytes: Int64) {
        guard var j = jobs[id], j.state == .uploading else { return }
        j.bytesDone = min(max(0, bytes), j.bytesTotal)
        jobs[id] = j
        persist() // coalesced (~500 ms)
        publish() // coalesced (~100 ms, TRANSFERS.md §4)
    }

    // MARK: scheduler

    /// Next startable queued id (FIFO), skipping stale entries.
    private func popQueued() -> UUID? {
        while fifoHead < fifo.count {
            let id = fifo[fifoHead]
            fifoHead += 1
            // An id whose previous run is still unwinding (paused then
            // resumed fast) is skipped: that run's exit re-queues it.
            // B12: another account's job is skipped (its entry is dropped;
            // `setAccountScope` re-queues it when that account is back).
            if jobs[id]?.state == .queued, inFlight[id] == nil, isVisible(id) { return id }
        }
        return nil
    }

    private func compactFIFO() {
        if fifoHead == fifo.count {
            fifo.removeAll(keepingCapacity: true)
            fifoHead = 0
        } else if fifoHead > 1024, fifoHead * 2 > fifo.count {
            fifo.removeFirst(fifoHead)
            fifoHead = 0
        }
    }

    private func pump() {
        guard let uploader else { return }
        var started = false
        while inFlight.count < maxConcurrentUploads, let id = popQueued() {
            jobs[id]?.state = .uploading
            jobs[id]?.updatedAt = Date()
            nextGeneration &+= 1
            let generation = nextGeneration
            inFlight[id] = generation
            tasks[id] = Task { await self.run(id: id, generation: generation, uploader: uploader) }
            started = true
        }
        compactFIFO()
        if started {
            persist(urgent: true)
            publish()
        }
    }

    /// True while `generation` is still the run that owns `id`'s slot.
    /// Every write a run makes is gated on this (plus a state check), so a
    /// stale run can never touch a newer run's job, task or slot.
    private func owns(_ id: UUID, _ generation: UInt64) -> Bool {
        inFlight[id] == generation
    }

    private func run(id: UUID, generation: UInt64, uploader: any TransferUploader) async {
        defer {
            if owns(id, generation) {
                inFlight[id] = nil
                tasks[id] = nil
                // Resumed while this run was unwinding: back in line.
                if jobs[id]?.state == .queued { fifo.append(id) }
                // Cancelled or removed mid-upload: the job never runs
                // again, so its draft is discarded here (F8.2 review).
                if let removed = removedInFlight.removeValue(forKey: id) {
                    scheduleDiscard(removed, using: uploader)
                } else if let j = jobs[id], j.state == .cancelled {
                    scheduleDiscard(j, using: uploader)
                }
            }
            persist(urgent: true)
            publish()
            pump()
        }
        guard owns(id, generation), var first = jobs[id], first.state == .uploading else { return }
        if first.clientUID == nil { // jobs persisted before F8.2-R3
            first.clientUID = UUID().uuidString
            jobs[id] = first
        }
        var job = first
        let events = TransferUploadEvents(
            draftCreated: { [self] linkID, revisionID in
                await self.recordDraft(id: id, generation: generation, linkID: linkID, revisionID: revisionID)
            },
            bookmarkRefreshed: { [self] bookmark in
                await self.recordBookmark(id: id, generation: generation, bookmark: bookmark)
            },
            commitSending: { [self] in
                await self.recordCommitSending(id: id, generation: generation)
            }
        )
        // Attempt loop: transient failures back off in-slot; pause/cancel win.
        while true {
            do {
                let linkID = try await uploader.upload(
                    job: job,
                    progress: { [self] done in await self.reportProgress(id: id, bytes: done) },
                    events: events
                )
                // The server committed the file. Record it even if the job
                // was paused (or paused+resumed) meanwhile: discarding the
                // success would make the next run upload it a second time.
                // A removed job stays removed (its draft is now a real
                // file — nothing to discard).
                guard owns(id, generation), var done = jobs[id] else {
                    if owns(id, generation) { removedInFlight[id] = nil }
                    return
                }
                done.state = .done
                done.bytesDone = done.bytesTotal
                done.remoteLinkID = linkID
                done.draftLinkID = nil
                done.draftRevisionID = nil
                done.draftCommitSent = false
                done.errorMessage = nil
                done.errorCode = nil
                done.updatedAt = Date()
                jobs[id] = done
                return
            } catch {
                // Whoever stopped this job (pause / cancel / remove /
                // sign-out) already set its state: a late error from the
                // aborted upload must never overwrite it with `.failed`.
                guard owns(id, generation), jobs[id]?.state == .uploading else { return }
                let failure = TransferErrorClassify.classify(error)
                switch failure {
                case .cancelled:
                    // Cancelled without an operator transition (e.g. the
                    // system tore the request down): park it, never fail it.
                    jobs[id]?.state = .paused
                    jobs[id]?.updatedAt = Date()
                    return
                case .needsHumanVerification:
                    pauseAll() // HV 9001: whole queue pauses (TRANSFERS.md §3)
                    return
                case let .permanent(message):
                    guard var failed = jobs[id] else { return }
                    failed.attempt += 1
                    failed.state = .failed
                    failed.errorMessage = message
                    failed.errorCode = TransferErrorClassify.protonCode(error)
                    failed.updatedAt = Date()
                    jobs[id] = failed
                    return
                case let .transient(message):
                    guard var retrying = jobs[id] else { return }
                    retrying.attempt += 1
                    retrying.errorMessage = message
                    retrying.errorCode = TransferErrorClassify.protonCode(error)
                    retrying.updatedAt = Date()
                    jobs[id] = retrying
                    job = retrying // carries the persisted draft IDs into the retry
                    if job.attempt >= job.maxAttempts {
                        jobs[id]?.state = .failed
                        return
                    }
                    persist(urgent: true)
                    publish()
                    await sleeper(TransferRetryPolicy.delayNanoseconds(
                        failures: job.attempt,
                        jitter: TransferRetryPolicy.randomJitter(),
                        retryAfter: TransferErrorClassify.retryAfter(error)
                    ))
                    // Pause/cancel/remove during backoff wins over the retry.
                    guard owns(id, generation), jobs[id]?.state == .uploading,
                          !Task.isCancelled
                    else { return }
                }
            }
        }
    }

    /// Persists the draft the current attempt created (F8.2-R3), so the
    /// next attempt — even after a crash — can delete it.
    /// A removed job's still-unwinding run records into `removedInFlight`
    /// so its exit discards the right draft.
    private func recordDraft(id: UUID, generation: UInt64, linkID: String, revisionID: String) {
        guard owns(id, generation) else { return }
        mutateRunJob(id) {
            $0.draftLinkID = linkID
            $0.draftRevisionID = revisionID
            $0.draftCommitSent = false
        }
    }

    /// The current draft's commit is going out (F8.2 review).
    private func recordCommitSending(id: UUID, generation: UInt64) {
        guard owns(id, generation) else { return }
        mutateRunJob(id) { $0.draftCommitSent = true }
    }

    private func mutateRunJob(_ id: UUID, _ change: (inout TransferJob) -> Void) {
        if var j = jobs[id] {
            change(&j)
            jobs[id] = j
            persist(urgent: true)
        } else if var r = removedInFlight[id] {
            change(&r)
            removedInFlight[id] = r
        }
    }

    // MARK: draft cleanup (F8.2 review)

    /// Discards `job`'s server draft in a DETACHED task: it must not
    /// inherit a cancelled upload's cancellation (URLSession would abort
    /// the delete) nor wait on the slot. Success clears the persisted
    /// draft IDs (if the job still exists and still points at that draft);
    /// failure keeps them — a relaunch's FileDraftFlow deletes the draft.
    private func scheduleDiscard(_ job: TransferJob, using uploader: (any TransferUploader)?) {
        guard let linkID = job.draftLinkID, let uploader else { return }
        nextCleanup &+= 1
        let token = nextCleanup
        cleanups[token] = Task.detached { [self] in
            let discarded = (try? await uploader.discardDraft(job: job)) != nil
            await self.cleanupFinished(token, id: job.id, linkID: linkID, discarded: discarded)
        }
    }

    private func cleanupFinished(_ token: UInt64, id: UUID, linkID: String, discarded: Bool) {
        cleanups[token] = nil
        guard discarded, var j = jobs[id], j.draftLinkID == linkID, inFlight[id] == nil else { return }
        j.draftLinkID = nil
        j.draftRevisionID = nil
        j.draftCommitSent = false
        jobs[id] = j
        persist(urgent: true)
    }

    /// Test seam: waits for every scheduled draft cleanup.
    func waitForDraftCleanups() async {
        while let next = cleanups.first {
            await next.value.value
            cleanups[next.key] = nil
        }
    }

    /// Persists a re-created (previously stale) bookmark (F8.2-R4).
    private func recordBookmark(id: UUID, generation: UInt64, bookmark: Data) {
        guard owns(id, generation), var j = jobs[id] else { return }
        j.localBookmark = bookmark
        jobs[id] = j
        persist(urgent: true)
    }

    // MARK: persistence (coalesced; F8.2-R2)

    /// Writes any pending snapshot change now (app quit, tests).
    func flush() {
        if dirty || needsBackup { writeSnapshot() }
    }

    /// Marks the snapshot dirty. `urgent` (state transitions) writes at
    /// once when no save ran within the debounce window; otherwise — and
    /// always for progress — one trailing save covers everything.
    private func persist(urgent: Bool = false) {
        guard store != nil else { return }
        dirty = true
        let window = Double(saveDebounceNanoseconds) / 1_000_000_000
        let elapsed = now().timeIntervalSince(lastSave)
        if urgent, elapsed >= window {
            writeSnapshot()
            return
        }
        guard !saveScheduled else { return }
        saveScheduled = true
        let wait = UInt64(max(0, window - max(0, elapsed)) * 1_000_000_000)
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: max(wait, 1_000_000))
            await self?.trailingSave()
        }
    }

    private func trailingSave() {
        saveScheduled = false
        if dirty { writeSnapshot() }
    }

    private func writeSnapshot() {
        guard let store else { return }
        dirty = false
        lastSave = now()
        guard let data = try? TransferQueueSnapshot.encode(order.compactMap { jobs[$0] }) else { return }
        if needsBackup {
            // Something in the loaded file could not be decoded: keep the
            // original next to it before the first overwrite.
            store.backup()
            needsBackup = false
        }
        try? store.write(data)
        saveCount += 1
    }

    /// Delivers a snapshot to the listener, coalesced: immediately when the
    /// last delivery is older than the interval, else one trailing delivery.
    private func publish() {
        guard listener != nil else { return }
        let window = Double(notifyIntervalNanoseconds) / 1_000_000_000
        let elapsed = now().timeIntervalSince(lastNotify)
        if elapsed >= window, !notifyScheduled {
            deliver()
            return
        }
        guard !notifyScheduled else { return }
        notifyScheduled = true
        let wait = UInt64(max(0, window - max(0, elapsed)) * 1_000_000_000)
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: max(wait, 1_000_000))
            await self?.trailingDeliver()
        }
    }

    private func trailingDeliver() {
        notifyScheduled = false
        deliver()
    }

    private func deliver() {
        guard let listener else { return }
        lastNotify = now()
        listener(snapshot())
    }
}
