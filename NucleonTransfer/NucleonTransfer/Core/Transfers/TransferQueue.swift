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
/// - Retry: transient errors back off in-slot (the slot is held during the
///   sleep); pause/cancel win over a pending retry.
/// - Backoff sleeping is injectable (`sleeper`) so tests never wait.
/// - No uploader set (pre-login) → jobs accumulate `queued`; `start()` pumps.
actor TransferQueue {
    private var jobs: [UUID: TransferJob] = [:]
    /// Insertion order (stable UI listing + FIFO scheduling).
    private var order: [UUID] = []
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
    private let storeURL: URL?
    /// UI hook: receives full snapshots (UI throttles/observes as it likes).
    var listener: (@Sendable ([TransferJob]) -> Void)?

    var maxConcurrentUploads: Int
    /// Backoff wait; default = real Task.sleep (cancellable).
    var sleeper: @Sendable (UInt64) async -> Void = { ns in
        try? await Task.sleep(nanoseconds: ns)
    }

    private var lastSave = Date.distantPast
    private var lastNotify = Date.distantPast

    init(
        storeURL: URL? = nil,
        uploader: (any TransferUploader)? = nil,
        maxConcurrentUploads: Int = 3
    ) {
        self.storeURL = storeURL
        self.uploader = uploader
        self.maxConcurrentUploads = maxConcurrentUploads
        if let storeURL,
           let data = try? Data(contentsOf: storeURL),
           let saved = try? JSONDecoder().decode([TransferJob].self, from: data)
        {
            for var job in saved {
                if job.state == .uploading { job.state = .queued } // resume after relaunch
                job.updatedAt = Date()
                jobs[job.id] = job
                order.append(job.id)
            }
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

    func setMaxConcurrent(_ n: Int) {
        maxConcurrentUploads = n
    }

    func setListener(_ l: (@Sendable ([TransferJob]) -> Void)?) {
        listener = l
    }

    // MARK: enqueue

    func enqueue(_ job: TransferJob) {
        var j = job
        j.updatedAt = Date()
        jobs[j.id] = j
        if !order.contains(j.id) { order.append(j.id) }
        save(force: true)
        notify(force: true)
        pump()
    }

    func enqueueMany(_ newJobs: [TransferJob]) {
        for var j in newJobs {
            j.updatedAt = Date()
            jobs[j.id] = j
            if !order.contains(j.id) { order.append(j.id) }
        }
        save(force: true)
        notify(force: true)
        pump()
    }

    /// Uploads a scanned local tree: creates remote folders parent→child
    /// (memoized per relative path), then enqueues one job per file with the
    /// resolved parent LinkID. `rootParentLinkID` is the existing remote
    /// folder the tree lands in; the scan root itself is never created.
    /// - Returns: enqueued job IDs (folders return their LinkIDs via `createdFolders`).
    @discardableResult
    func enqueueTree(
        entries: [LocalTreeScan.Entry],
        shareID: String,
        rootParentLinkID: String,
        folders: any RemoteFolderCreator,
        maxAttempts: Int = 5
    ) async throws -> [UUID] {
        var remoteByRelPath = ["": rootParentLinkID]
        let dirs = entries.filter(\.isDirectory)
            .sorted {
                let d0 = $0.relativePath.components(separatedBy: "/").count
                let d1 = $1.relativePath.components(separatedBy: "/").count
                if d0 != d1 { return d0 < d1 }
                return $0.relativePath < $1.relativePath
            }
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
        var enqueued: [UUID] = []
        for file in entries.filter({ !$0.isDirectory }) {
            let parentRel = (file.relativePath as NSString).deletingLastPathComponent
            let parent = remoteByRelPath[parentRel] ?? rootParentLinkID
            let name = (file.relativePath as NSString).lastPathComponent
            let job = TransferJob(
                fileName: name,
                relativePath: file.relativePath,
                localPath: file.url.path,
                shareID: shareID,
                parentLinkID: parent,
                bytesTotal: file.size,
                maxAttempts: maxAttempts
            )
            enqueue(job)
            enqueued.append(job.id)
        }
        return enqueued
    }

    // MARK: operators

    func snapshot() -> [TransferJob] {
        order.compactMap { jobs[$0] }
    }

    func job(id: UUID) -> TransferJob? { jobs[id] }

    /// Attaches a security-scoped bookmark after enqueue (live UI only).
    func setBookmark(id: UUID, _ bookmark: Data?) {
        guard var j = jobs[id] else { return }
        j.localBookmark = bookmark
        jobs[id] = j
        save(force: true)
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
        case .paused, .done, .failed, .cancelled:
            break
        }
        save(force: true)
        notify(force: true)
    }

    func pauseAll() {
        for id in order {
            guard var j = jobs[id] else { continue }
            if j.state == .queued || j.state == .uploading {
                j.state = .paused
                j.updatedAt = Date()
                jobs[id] = j
                tasks[id]?.cancel()
            }
        }
        save(force: true)
        notify(force: true)
    }

    func resume(id: UUID) {
        guard var j = jobs[id], j.state == .paused else { return }
        j.state = .queued
        j.errorMessage = nil
        j.updatedAt = Date()
        jobs[id] = j
        save(force: true)
        notify(force: true)
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
        case .done, .cancelled:
            break
        }
        save(force: true)
        notify(force: true)
    }

    /// Relaunch: failed/cancelled → fresh queued job (attempt + progress reset;
    /// F4.4 retries whole files — no partial-block resume yet, see docs).
    func relaunch(id: UUID) {
        guard var j = jobs[id] else { return }
        guard j.state == .failed || j.state == .cancelled else { return }
        j.state = .queued
        j.attempt = 0
        j.bytesDone = 0
        j.errorMessage = nil
        j.remoteLinkID = nil
        j.updatedAt = Date()
        jobs[id] = j
        save(force: true)
        notify(force: true)
        pump()
    }

    /// Relaunches every failed job (UI "retry all").
    func relaunchAllFailed() {
        var touched = false
        for id in order {
            guard var j = jobs[id], j.state == .failed else { continue }
            j.state = .queued
            j.attempt = 0
            j.bytesDone = 0
            j.errorMessage = nil
            j.remoteLinkID = nil
            j.updatedAt = Date()
            jobs[id] = j
            touched = true
        }
        if touched {
            save(force: true)
            notify(force: true)
            pump()
        }
    }

    /// Drops the job. A running upload is cancelled but keeps its slot
    /// (`inFlight`) until its task really returns — releasing it here let
    /// the pump start another upload while this one was still unwinding,
    /// exceeding the concurrency limit (F8.2-R1).
    func remove(id: UUID) {
        tasks[id]?.cancel()
        jobs[id] = nil
        order.removeAll { $0 == id }
        save(force: true)
        notify(force: true)
        pump()
    }

    func reportProgress(id: UUID, bytes: Int64) {
        guard var j = jobs[id], j.state == .uploading else { return }
        j.bytesDone = min(max(0, bytes), j.bytesTotal)
        jobs[id] = j
        save() // throttled; forced on state transitions
        notify() // throttled ~100ms (TRANSFERS.md §4)
    }

    // MARK: scheduler

    private func pump() {
        guard let uploader else { return }
        while inFlight.count < maxConcurrentUploads {
            // An id whose previous run is still unwinding (paused then
            // resumed fast) is skipped: that run's exit pumps again.
            guard let next = order.compactMap({ jobs[$0] })
                .first(where: { $0.state == .queued && inFlight[$0.id] == nil })
            else { break }
            let id = next.id
            jobs[id]?.state = .uploading
            jobs[id]?.updatedAt = Date()
            nextGeneration &+= 1
            let generation = nextGeneration
            inFlight[id] = generation
            tasks[id] = Task { await self.run(id: id, generation: generation, uploader: uploader) }
        }
        save(force: true)
        notify(force: true)
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
            }
            save(force: true)
            notify(force: true)
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
                    save(force: true)
                    notify(force: true)
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

    // MARK: persistence (throttled; forced on transitions)

    private func save(force: Bool = false) {
        guard let storeURL else { return }
        let now = Date()
        guard force || now.timeIntervalSince(lastSave) > 1 else { return }
        lastSave = now
        let snap = order.compactMap { jobs[$0] }
        guard let data = try? JSONEncoder().encode(snap) else { return }
        try? FileManager.default.createDirectory(
            at: storeURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? data.write(to: storeURL, options: .atomic)
    }

    private func notify(force: Bool = false) {
        guard let listener else { return }
        let now = Date()
        guard force || now.timeIntervalSince(lastNotify) > 0.1 else { return }
        lastNotify = now
        listener(order.compactMap { jobs[$0] })
    }
}
