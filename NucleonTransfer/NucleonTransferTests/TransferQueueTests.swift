// Nucleon Transfer — F4.4 offline queue suite (Swift Testing).
// No network, no secrets, no waiting on real backoff (injected sleeper).
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - mocks

/// Locked script box: per-call results + concurrency observation.
final class MockBox: @unchecked Sendable {
    private let lock = NSLock()
    var script: [Result<String?, any Error>] = []
    var workNanoseconds: UInt64 = 0
    private(set) var calls = 0
    private(set) var concurrent = 0
    private(set) var maxSeen = 0
    private(set) var progressReports: [Int64] = []

    func enter() {
        lock.withLock {
            calls += 1
            concurrent += 1
            maxSeen = max(maxSeen, concurrent)
        }
    }

    func leave() { lock.withLock { concurrent -= 1 } }

    func next() -> Result<String?, any Error>? {
        lock.withLock { script.isEmpty ? nil : script.removeFirst() }
    }

    func progress(_ n: Int64) { lock.withLock { progressReports.append(n) } }
}

struct MockUploader: TransferUploader {
    let box: MockBox
    func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
        box.enter()
        defer { box.leave() }
        if box.workNanoseconds > 0 { try await Task.sleep(nanoseconds: box.workNanoseconds) }
        switch box.next() ?? .success("link-\(job.fileName)") {
        case let .success(id):
            await progress(job.bytesTotal)
            box.progress(job.bytesTotal)
            return id
        case let .failure(e):
            throw e
        }
    }
}

final class MockFolders: @unchecked Sendable, RemoteFolderCreator {
    private let lock = NSLock()
    private(set) var calls: [(name: String, parent: String)] = []
    var error: (any Error)?

    func ensureFolder(name: String, parentLinkID: String, shareID: String) async throws -> String {
        lock.withLock { calls.append((name, parentLinkID)) }
        if let error { throw error }
        return "L-\(name)"
    }
}

/// Records backoff waits without sleeping.
actor RecordingSleeper {
    private(set) var waits: [UInt64] = []
    func sleep(_ ns: UInt64) async { waits.append(ns) }
}

// MARK: - helpers

func makeJob(_ name: String = "a.txt", bytes: Int64 = 100, maxAttempts: Int = 5) -> TransferJob {
    TransferJob(
        fileName: name, relativePath: name, localPath: "/tmp/\(name)",
        shareID: "S", parentLinkID: "P", bytesTotal: bytes, maxAttempts: maxAttempts
    )
}

func makeQueue(box: MockBox? = nil, maxConcurrent: Int = 3) async -> (TransferQueue, RecordingSleeper) {
    let sleeper = RecordingSleeper()
    let q = TransferQueue(storeURL: nil, maxConcurrentUploads: maxConcurrent)
    if let box { await q.setUploader(MockUploader(box: box)) }
    await q.setSleeper { ns in await sleeper.sleep(ns) }
    return (q, sleeper)
}

func drain(_ q: TransferQueue, timeoutSeconds: Double = 10) async {
    let start = Date()
    while Date().timeIntervalSince(start) < timeoutSeconds {
        let s = await q.snapshot()
        if !s.contains(where: { $0.state == .queued || $0.state == .uploading }) { return }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
}

struct TransferQueueTests {
    // MARK: policy (pure)

    @Test func retryDelaysGrowAndCap() {
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1) == 1_000_000_000)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 2) == 2_000_000_000)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 3) == 4_000_000_000)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 7) == 60_000_000_000) // capped
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 100) == 60_000_000_000)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1, jitter: 500) == 1_000_000_500)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1, jitter: 5_000_000_000) == 2_000_000_000) // jitter capped at 1s
    }

    @Test func classifyMapsErrors() {
        #expect(TransferErrorClassify.classify(TransferFailure.transient("x")) == .transient("x"))
        #expect(TransferErrorClassify.classify(ProtonAPIError.api(code: 429, message: "slow")) == .transient("api 429: slow"))
        #expect(TransferErrorClassify.classify(ProtonAPIError.api(code: 503, message: "down")) == .transient("api 503: down"))
        #expect(TransferErrorClassify.classify(ProtonAPIError.api(code: 400, message: "bad")) == .permanent("api 400: bad"))
        #expect(TransferErrorClassify.classify(ProtonAPIError.api(code: 404, message: "no")) == .permanent("api 404: no"))
        #expect(TransferErrorClassify.classify(ProtonAPIError.humanVerificationRequired) == .needsHumanVerification)
        #expect(TransferErrorClassify.classify(ProtonAPIError.transport(URLError(.timedOut))) == .transient("copy network-unreachable"))
        #expect(TransferErrorClassify.classify(URLError(.networkConnectionLost)) == .transient("copy network-unreachable"))
    }

    // MARK: happy path + retry

    @Test func successMarksDone() async {
        let box = MockBox()
        let (q, _) = await makeQueue(box: box)
        await q.enqueue(makeJob(bytes: 42))
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs.count == 1)
        #expect(jobs[0].state == .done)
        #expect(jobs[0].bytesDone == 42)
        #expect(jobs[0].remoteLinkID == "link-a.txt")
        #expect(box.calls == 1)
        #expect(box.progressReports == [42])
    }

    @Test func transientRetriesWithBackoffThenSucceeds() async {
        let box = MockBox()
        box.script = [.failure(TransferFailure.transient("t1")), .failure(TransferFailure.transient("t2"))]
        let (q, sleeper) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs[0].state == .done)
        #expect(jobs[0].attempt == 2)
        #expect(box.calls == 3)
        let waits = await sleeper.waits
        #expect(waits.count == 2)
        #expect(waits[0] >= 1_000_000_000 && waits[0] < 2_000_000_000) // 1s + jitter
        #expect(waits[1] >= 2_000_000_000 && waits[1] < 3_000_000_000) // 2s + jitter
    }

    @Test func permanentFailsFastWithoutRetry() async {
        let box = MockBox()
        box.script = [.failure(TransferFailure.permanent("bad request"))]
        let (q, sleeper) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs[0].state == .failed)
        #expect(jobs[0].errorMessage == "bad request")
        #expect(box.calls == 1)
        #expect(await sleeper.waits.isEmpty)
    }

    @Test func maxAttemptsExhaustsToFailed() async {
        let box = MockBox() // default script empty → would succeed; force transient loop
        box.script = Array(repeating: Result<String?, any Error>.failure(TransferFailure.transient("down")), count: 9)
        let (q, sleeper) = await makeQueue(box: box)
        await q.enqueue(makeJob(maxAttempts: 3))
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs[0].state == .failed)
        #expect(jobs[0].attempt == 3)
        #expect(box.calls == 3)
        #expect(await sleeper.waits.count == 2)
    }

    // MARK: concurrency

    @Test func concurrencyLimitRespected() async {
        let box = MockBox()
        box.workNanoseconds = 100_000_000 // 100ms per upload
        let (q, _) = await makeQueue(box: box, maxConcurrent: 3)
        await q.enqueueMany((0..<6).map { makeJob("f\($0).txt") })
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs.allSatisfy { $0.state == .done })
        #expect(box.maxSeen == 3)
        #expect(box.calls == 6)
    }

    // MARK: operators

    @Test func pauseQueuedThenResume() async {
        let box = MockBox()
        let (q, _) = await makeQueue(box: box)
        let job = makeJob()
        await q.enqueue(job)
        await q.pause(id: job.id) // may race the instant mock; either paused or done
        var s = await q.job(id: job.id)?.state
        if s == .paused {
            #expect(box.calls <= 1)
            await q.resume(id: job.id)
            await drain(q)
            s = await q.job(id: job.id)?.state
            #expect(s == .done)
        } else {
            #expect(s == .done) // mock won the race — acceptable
        }
    }

    @Test func pauseUploadingWins() async {
        let box = MockBox()
        box.workNanoseconds = 500_000_000
        let (q, _) = await makeQueue(box: box)
        let job = makeJob()
        await q.enqueue(job)
        // Wait until actually uploading, then pause.
        let start = Date()
        while await q.job(id: job.id)?.state != .uploading, Date().timeIntervalSince(start) < 5 {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(await q.job(id: job.id)?.state == .uploading)
        await q.pause(id: job.id)
        await drain(q)
        #expect(await q.job(id: job.id)?.state == .paused)
    }

    @Test func cancelUploadingMarksCancelled() async {
        let box = MockBox()
        box.workNanoseconds = 500_000_000
        let (q, _) = await makeQueue(box: box)
        let job = makeJob()
        await q.enqueue(job)
        let start = Date()
        while await q.job(id: job.id)?.state != .uploading, Date().timeIntervalSince(start) < 5 {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        await q.cancel(id: job.id)
        await drain(q)
        #expect(await q.job(id: job.id)?.state == .cancelled)
    }

    @Test func relaunchResetsAndSucceeds() async {
        let box = MockBox()
        box.script = [.failure(TransferFailure.permanent("nope"))]
        let (q, _) = await makeQueue(box: box)
        let job = makeJob()
        await q.enqueue(job)
        await drain(q)
        #expect(await q.job(id: job.id)?.state == .failed)
        await q.relaunch(id: job.id)
        await drain(q)
        let done = await q.job(id: job.id)
        #expect(done?.state == .done)
        #expect(done?.attempt == 0)
        #expect(done?.bytesDone == done?.bytesTotal)
        #expect(box.calls == 2)
    }

    @Test func humanVerificationPausesWholeQueue() async {
        let box = MockBox()
        box.script = [.failure(TransferFailure.needsHumanVerification)]
        let (q, _) = await makeQueue(box: box, maxConcurrent: 1)
        await q.enqueueMany([makeJob("a.txt"), makeJob("b.txt")])
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs.allSatisfy { $0.state == .paused })
        #expect(box.calls == 1) // second job never started
    }

    @Test func listenerReceivesSnapshots() async {
        let box = MockBox()
        let q = TransferQueue(storeURL: nil, maxConcurrentUploads: 3)
        await q.setUploader(MockUploader(box: box))
        await q.setSleeper { _ in }
        let seen = MockSeen()
        await q.setListener { snap in Task { await seen.append(snap.count) } }
        await q.enqueue(makeJob())
        await drain(q)
        #expect(await seen.counts.contains(1))
    }

    // MARK: tree enqueue (folders parent→child)

    @Test func treeEnqueueCreatesFoldersInOrder() async {
        let folders = MockFolders()
        let (q, _) = await makeQueue() // no uploader → jobs stay queued
        let root = URL(fileURLWithPath: "/drop")
        func e(_ rel: String, dir: Bool) -> LocalTreeScan.Entry {
            LocalTreeScan.Entry(
                url: root.appendingPathComponent(rel),
                relativePath: rel, isDirectory: dir,
                size: dir ? 0 : 10
            )
        }
        let entries = [
            e("", dir: true), e("a", dir: true), e("a/b", dir: true),
            e("top.txt", dir: false), e("a/mid.txt", dir: false), e("a/b/deep.txt", dir: false),
        ]
        let ids = try? await q.enqueueTree(
            entries: entries, shareID: "S", rootParentLinkID: "ROOT", folders: folders
        )
        #expect(ids?.count == 3)
        #expect(folders.calls.map(\.name) == ["a", "b"])
        #expect(folders.calls[0].parent == "ROOT")
        #expect(folders.calls[1].parent == "L-a") // child under created parent
        let jobs = await q.snapshot()
        #expect(jobs.count == 3)
        #expect(jobs.allSatisfy { $0.state == .queued && $0.shareID == "S" })
        let byRel = Dictionary(uniqueKeysWithValues: jobs.map { ($0.relativePath, $0) })
        #expect(byRel["top.txt"]?.parentLinkID == "ROOT")
        #expect(byRel["a/mid.txt"]?.parentLinkID == "L-a")
        #expect(byRel["a/b/deep.txt"]?.parentLinkID == "L-b")
    }

    // MARK: scan (real temp tree)

    @Test func scanPreservesStructureAndSkipsHidden() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("ntscan-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("hi".utf8).write(to: root.appendingPathComponent("a.txt"))
        try Data().write(to: root.appendingPathComponent("empty.txt"))
        try Data("x".utf8).write(to: root.appendingPathComponent(".hidden"))
        let sub = root.appendingPathComponent("sub")
        let deep = sub.appendingPathComponent("deep")
        try FileManager.default.createDirectory(at: deep, withIntermediateDirectories: true)
        try Data(repeating: 7, count: 256).write(to: deep.appendingPathComponent("c.bin"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("emptydir"), withIntermediateDirectories: true)

        let result = try LocalTreeScan.collect(root: root)
        let rels = result.entries.map(\.relativePath)
        #expect(!rels.contains(".hidden"))
        #expect(rels.contains(""))
        #expect(rels.contains("sub"))
        #expect(rels.contains("sub/deep"))
        #expect(rels.contains("emptydir"))
        // Topological: every dir precedes its children.
        let idx = Dictionary(uniqueKeysWithValues: rels.enumerated().map { ($1, $0) })
        #expect(idx[""]! < idx["sub"]!)
        #expect(idx["sub"]! < idx["sub/deep"]!)
        let files = result.entries.filter { !$0.isDirectory }
        #expect(files.count == 3)
        let sizes = Dictionary(uniqueKeysWithValues: files.map { ($0.relativePath, $0.size) })
        #expect(sizes["a.txt"] == 2)
        #expect(sizes["empty.txt"] == 0)
        #expect(sizes["sub/deep/c.bin"] == 256)
    }

    @Test func scanSkipsOutsideSymlinks() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("ntlink-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let outside = FileManager.default.temporaryDirectory
            .appendingPathComponent("ntlink-outside-\(UUID().uuidString).txt")
        try Data("secret".utf8).write(to: outside)
        defer { try? FileManager.default.removeItem(at: outside) }
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("escape"),
            withDestinationURL: outside
        )
        let result = try LocalTreeScan.collect(root: root)
        #expect(result.skippedOutsideSymlinks == 1)
        #expect(!result.entries.map(\.relativePath).contains("escape"))
    }

    // MARK: persistence

    @Test func snapshotRoundTripResetsUploadingAndKeepsDone() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ntq-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("q.json")
        var done = makeJob("done.txt")
        done.state = .done
        done.bytesDone = done.bytesTotal
        var flying = makeJob("flying.txt")
        flying.state = .uploading // crash mid-upload
        flying.attempt = 2
        try JSONEncoder().encode([done, flying]).write(to: url, options: .atomic)
        let q = TransferQueue(storeURL: url)
        let jobs = await q.snapshot()
        #expect(jobs.count == 2)
        #expect(jobs.first { $0.relativePath == "done.txt" }?.state == .done)
        let resumed = jobs.first { $0.relativePath == "flying.txt" }
        #expect(resumed?.state == .queued) // uploading → queued on relaunch
        #expect(resumed?.attempt == 2) // persistent counter survives
    }

    @Test func snapshotHoldsNoSecrets() throws {
        let job = makeJob()
        let json = String(data: try JSONEncoder().encode([job]), encoding: .utf8)!.lowercased()
        for banned in ["seed", "token", "passphrase", "secret", "accesstoken", "refresh"] {
            #expect(!json.contains(banned), "snapshot leaks \(banned)")
        }
        #expect(json.contains("localpath")) // paths/IDs/progress only
    }
}

actor MockSeen {
    private(set) var counts: [Int] = []
    func append(_ n: Int) { counts.append(n) }
}
