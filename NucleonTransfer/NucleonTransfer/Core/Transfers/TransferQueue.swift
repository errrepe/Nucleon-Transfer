// Nucleon Transfer — upload queue core (F4.4).
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
    var createdAt: Date
    var updatedAt: Date
    /// Remote LinkID after a successful upload.
    var remoteLinkID: String?

    enum CodingKeys: String, CodingKey {
        case id, fileName, relativePath, localPath, localBookmark, shareID,
             parentLinkID, state, bytesTotal, bytesDone, attempt, maxAttempts,
             errorMessage, createdAt, updatedAt, remoteLinkID
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
        createdAt = (try? c.decodeIfPresent(Date.self, forKey: .createdAt)) ?? Date()
        updatedAt = (try? c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
        remoteLinkID = try c.decodeIfPresent(String.self, forKey: .remoteLinkID)
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
        maxAttempts: Int = 5
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
            case .rateLimited:
                // Login-rate-limit shape reused defensively: surface, don't spin.
                return .permanent("rate limited")
            default:
                return .permanent(api.localizedDescription)
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
                return .transient(ns.localizedDescription)
            default:
                return .permanent(ns.localizedDescription)
            }
        }
        return .permanent(error.localizedDescription)
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

    static func delayNanoseconds(failures: Int, jitter: UInt64 = 0) -> UInt64 {
        let n = max(1, failures)
        // 2^(n-1), saturated before the shift can overflow.
        let shift = min(n - 1, 10)
        let exponential = baseNanoseconds << shift
        let capped = min(capNanoseconds, exponential)
        return capped + min(jitter, maxJitterNanoseconds)
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
    private var uploader: (any TransferUploader)?
    private let store: (any TransferQueueStore)?
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
        maxConcurrentUploads: Int = 3
    ) {
        self.init(
            store: storeURL.map { FileTransferQueueStore(url: $0) as any TransferQueueStore },
            uploader: uploader,
            maxConcurrentUploads: maxConcurrentUploads
        )
    }

    init(
        store: (any TransferQueueStore)?,
        uploader: (any TransferUploader)? = nil,
        maxConcurrentUploads: Int = 3
    ) {
        self.store = store
        self.uploader = uploader
        self.maxConcurrentUploads = maxConcurrentUploads
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

    // MARK: enqueue

    func enqueue(_ job: TransferJob) {
        enqueueMany([job])
    }

    /// Adds jobs in one batch: one snapshot write + one notification for
    /// the whole batch (F8.2-R2 — per-file saves made big drops quadratic).
    func enqueueMany(_ newJobs: [TransferJob]) {
        guard !newJobs.isEmpty else { return }
        let stamp = Date()
        for var j in newJobs {
            j.updatedAt = stamp
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
    /// - Returns: enqueued job IDs, in file-entry order.
    @discardableResult
    func enqueueTree(
        entries: [LocalTreeScan.Entry],
        shareID: String,
        rootParentLinkID: String,
        folders: any RemoteFolderCreator,
        maxAttempts: Int = 5
    ) async throws -> [UUID] {
        var remoteByRelPath = ["": rootParentLinkID]
        func depth(_ rel: String) -> Int {
            rel.isEmpty ? 0 : rel.utf8.reduce(1) { $1 == UInt8(ascii: "/") ? $0 + 1 : $0 }
        }
        let dirs = entries.filter(\.isDirectory)
            .map { (depth: depth($0.relativePath), entry: $0) }
            .sorted {
                if $0.depth != $1.depth { return $0.depth < $1.depth }
                return $0.entry.relativePath < $1.entry.relativePath
            }
            .map(\.entry)
        for dir in dirs where !dir.relativePath.isEmpty {
            let rel = dir.relativePath
            if remoteByRelPath[rel] != nil { continue } // idempotent within a tree
            let parentRel = (rel as NSString).deletingLastPathComponent
            let parent = remoteByRelPath[parentRel] ?? rootParentLinkID
            let name = ((rel as NSString).lastPathComponent as String)
                .precomposedStringWithCanonicalMapping
            let linkID = try await folders.ensureFolder(name: name, parentLinkID: parent, shareID: shareID)
            remoteByRelPath[rel] = linkID
        }
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

    // MARK: operators

    func snapshot() -> [TransferJob] {
        order.compactMap { jobs[$0] }
    }

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
        guard var j = jobs[id] else { return }
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

    func pauseAll() {
        var touched = false
        for id in order {
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

    func resume(id: UUID) {
        guard var j = jobs[id], j.state == .paused else { return }
        j.state = .queued
        j.errorMessage = nil
        j.updatedAt = Date()
        jobs[id] = j
        fifo.append(id)
        persist(urgent: true)
        publish()
        pump()
    }

    func cancel(id: UUID) {
        guard var j = jobs[id] else { return }
        switch j.state {
        case .queued, .uploading, .paused, .failed:
            j.state = .cancelled
            j.updatedAt = Date()
            jobs[id] = j
            tasks[id]?.cancel()
            persist(urgent: true)
            publish()
        case .done, .cancelled:
            break
        }
    }

    /// Relaunch: failed/cancelled → fresh queued job (attempt + progress reset;
    /// F4.4 retries whole files — no partial-block resume yet, see docs).
    func relaunch(id: UUID) {
        guard var j = jobs[id] else { return }
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
        for id in order {
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
        j.remoteLinkID = nil
        j.updatedAt = Date()
    }

    /// Drops the job. A running upload is cancelled but keeps its slot
    /// (`inFlight`) until its task really returns — releasing it here let
    /// the pump start another upload while this one was still unwinding,
    /// exceeding the concurrency limit (F8.2-R1).
    func remove(id: UUID) {
        tasks[id]?.cancel()
        guard jobs[id] != nil else { return }
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
            if jobs[id]?.state == .queued, inFlight[id] == nil { return id }
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
            }
            persist(urgent: true)
            publish()
            pump()
        }
        guard owns(id, generation), let first = jobs[id], first.state == .uploading else { return }
        var job = first
        // Attempt loop: transient failures back off in-slot; pause/cancel win.
        while true {
            do {
                let linkID = try await uploader.upload(
                    job: job,
                    progress: { [self] done in await self.reportProgress(id: id, bytes: done) }
                )
                // The server committed the file. Record it even if the job
                // was paused (or paused+resumed) meanwhile: discarding the
                // success would make the next run upload it a second time.
                // A removed job stays removed.
                guard owns(id, generation), var done = jobs[id] else { return }
                done.state = .done
                done.bytesDone = done.bytesTotal
                done.remoteLinkID = linkID
                done.errorMessage = nil
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
                    failed.updatedAt = Date()
                    jobs[id] = failed
                    return
                case let .transient(message):
                    guard var retrying = jobs[id] else { return }
                    retrying.attempt += 1
                    retrying.errorMessage = message
                    retrying.updatedAt = Date()
                    jobs[id] = retrying
                    job = retrying
                    if job.attempt >= job.maxAttempts {
                        jobs[id]?.state = .failed
                        return
                    }
                    persist(urgent: true)
                    publish()
                    await sleeper(TransferRetryPolicy.delayNanoseconds(
                        failures: job.attempt,
                        jitter: TransferRetryPolicy.randomJitter()
                    ))
                    // Pause/cancel/remove during backoff wins over the retry.
                    guard owns(id, generation), jobs[id]?.state == .uploading,
                          !Task.isCancelled
                    else { return }
                }
            }
        }
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
        listener(order.compactMap { jobs[$0] })
    }
}
