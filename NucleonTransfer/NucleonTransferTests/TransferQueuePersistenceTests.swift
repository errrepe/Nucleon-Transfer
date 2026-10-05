// Nucleon Transfer — F8.2-R2 queue persistence & scale (Swift Testing).
// Batch enqueue, coalesced saves, FIFO scheduling, lossy versioned decode
// with `.bak`, legacy flat-array snapshots.
import Foundation
import Testing

@testable import NucleonTransfer

/// In-memory store that counts writes/backups.
final class CountingStore: TransferQueueStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    private(set) var writes = 0
    private(set) var backups: [Data] = []

    init(initial: Data? = nil) { data = initial }

    func read() -> Data? { lock.withLock { data } }

    func write(_ d: Data) throws {
        lock.withLock {
            data = d
            writes += 1
        }
    }

    func backup() {
        lock.withLock { if let data { backups.append(data) } }
    }

    var writeCount: Int { lock.withLock { writes } }
    var backupCount: Int { lock.withLock { backups.count } }
}

/// Reports many small progress steps, then succeeds; records start order.
final class ProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var started: [String] = []
    var steps = 200
    func start(_ name: String) { lock.withLock { started.append(name) } }
    var order: [String] { lock.withLock { started } }
}

struct ChattyUploader: TransferUploader {
    let box: ProgressBox
    func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
        box.start(job.fileName)
        for i in 1...box.steps {
            await progress(job.bytesTotal * Int64(i) / Int64(box.steps))
        }
        return "L-\(job.fileName)"
    }
}

private func treeEntries(files: Int) -> [LocalTreeScan.Entry] {
    let root = URL(fileURLWithPath: "/drop")
    var entries = [LocalTreeScan.Entry(url: root, relativePath: "", isDirectory: true, size: 0)]
    for d in 0..<10 {
        entries.append(LocalTreeScan.Entry(
            url: root.appendingPathComponent("d\(d)"), relativePath: "d\(d)", isDirectory: true, size: 0
        ))
    }
    for i in 0..<files {
        let rel = "d\(i % 10)/f\(i).txt"
        entries.append(LocalTreeScan.Entry(
            url: root.appendingPathComponent(rel), relativePath: rel, isDirectory: false,
            size: 10, bookmark: Data([UInt8(i % 256)])
        ))
    }
    return entries
}

private func tempDir() throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ntq2-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

struct TransferQueuePersistenceTests {
    // MARK: scale

    @Test func enqueueTreeOf3kFilesIsOneBatch() async throws {
        let store = CountingStore()
        let q = TransferQueue(store: store) // no uploader → jobs stay queued
        let entries = treeEntries(files: 3000)
        let start = Date()
        let ids = try await q.enqueueTree(
            entries: entries, shareID: "S", rootParentLinkID: "ROOT", folders: MockFolders()
        )
        let elapsed = Date().timeIntervalSince(start)
        #expect(ids.count == 3000)
        #expect(elapsed < 2, "enqueue of 3k files took \(elapsed)s")
        #expect(store.writeCount <= 2, "saves: \(store.writeCount)")
        let jobs = await q.snapshot()
        #expect(jobs.count == 3000)
        // Bookmarks made during the scan travel into the jobs.
        #expect(jobs.allSatisfy { $0.localBookmark != nil })
        #expect(jobs.first { $0.relativePath == "d3/f3.txt" }?.parentLinkID == "L-d3")
    }

    @Test func progressSavesAreCoalesced() async {
        let store = CountingStore()
        let box = ProgressBox()
        box.steps = 300
        let q = TransferQueue(store: store, uploader: ChattyUploader(box: box))
        await q.setSleeper { _ in }
        await q.enqueue(makeJob(bytes: 3000))
        await drain(q)
        await q.flush()
        // 300 progress reports + transitions → a handful of writes, not 300+.
        #expect(store.writeCount < 20, "writes: \(store.writeCount)")
        let reloaded = TransferQueue(store: store)
        #expect(await reloaded.snapshot().first?.state == .done)
    }

    @Test func flushWritesPendingChanges() async {
        let store = CountingStore()
        let q = TransferQueue(store: store)
        await q.setCoalescing(saveDebounceNanoseconds: 60_000_000_000) // trailing save never fires in-test
        let a = makeJob("a.txt")
        let b = makeJob("b.txt")
        await q.enqueue(a) // leading-edge write
        await q.enqueue(b) // inside the window → only marked dirty
        #expect(store.writeCount == 1)
        await q.flush()
        #expect(store.writeCount == 2)
        let reloaded = TransferQueue(store: store)
        #expect(await reloaded.snapshot().map(\.fileName) == ["a.txt", "b.txt"])
    }

    // MARK: FIFO scheduling

    @Test func fifoStartsJobsInEnqueueOrderAndResumeGoesLast() async {
        let box = ProgressBox()
        box.steps = 1
        let q = TransferQueue(storeURL: nil, maxConcurrentUploads: 1)
        await q.setSleeper { _ in }
        let jobs = (0..<5).map { makeJob("f\($0).txt") }
        await q.enqueueMany(jobs) // no uploader yet: all queued
        await q.pause(id: jobs[1].id)
        await q.resume(id: jobs[1].id) // re-queued at the back
        await q.setUploader(ChattyUploader(box: box))
        await q.start()
        await drain(q)
        #expect(box.order == ["f0.txt", "f1.txt", "f2.txt", "f3.txt", "f4.txt"]
            || box.order == ["f0.txt", "f2.txt", "f3.txt", "f4.txt", "f1.txt"])
        #expect(box.order.count == 5) // never started twice
        #expect(await q.snapshot().allSatisfy { $0.state == .done })
    }

    // MARK: lossy, versioned decode

    @Test func oneInvalidJobKeepsTheOthersAndWritesBak() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("transfer-queue.json")
        let good1 = makeJob("good1.txt")
        let good2 = makeJob("good2.txt")
        let enc = JSONEncoder()
        let g1 = try #require(String(data: try enc.encode(good1), encoding: .utf8))
        let g2 = try #require(String(data: try enc.encode(good2), encoding: .utf8))
        let bad = #"{"id":"not-a-uuid","fileName":42}"#
        let original = Data(#"{"schemaVersion":2,"jobs":[\#(g1),\#(bad),\#(g2)]}"#.utf8)
        try original.write(to: url)

        let q = TransferQueue(storeURL: url)
        #expect(await q.snapshot().map(\.fileName) == ["good1.txt", "good2.txt"])
        await q.flush() // first overwrite
        let bak = dir.appendingPathComponent("transfer-queue.json.bak")
        #expect(try Data(contentsOf: bak) == original)
        // Rewritten file is the clean v2 envelope.
        let rewritten = TransferQueueSnapshot.decode(try Data(contentsOf: url))
        #expect(!rewritten.lossy)
        #expect(rewritten.jobs.count == 2)
    }

    @Test func garbageFileIsBackedUpNotSilentlyLost() async throws {
        let store = CountingStore(initial: Data("{not json".utf8))
        let q = TransferQueue(store: store)
        #expect(await q.snapshot().isEmpty)
        await q.enqueue(makeJob())
        #expect(store.backupCount == 1)
    }

    @Test func legacyFlatArrayStillLoads() async throws {
        var a = makeJob("old.txt")
        a.state = .failed
        a.errorMessage = "boom"
        let legacy = try JSONEncoder().encode([a])
        let store = CountingStore(initial: legacy)
        let q = TransferQueue(store: store)
        let jobs = await q.snapshot()
        #expect(jobs.count == 1)
        #expect(jobs[0].state == .failed)
        #expect(jobs[0].errorMessage == "boom")
        await q.enqueue(makeJob("new.txt"))
        #expect(store.backupCount == 0) // lossless legacy load needs no .bak
        let decoded = TransferQueueSnapshot.decode(try #require(store.read()))
        #expect(decoded.jobs.map(\.fileName) == ["old.txt", "new.txt"])
    }

    @Test func missingOptionalFieldsDefault() throws {
        let id = UUID()
        let minimal = Data(#"""
        {"schemaVersion":2,"jobs":[{"id":"\#(id.uuidString)","fileName":"m.txt",
        "localPath":"/tmp/m.txt","shareID":"S","parentLinkID":"P","state":"someFutureState"}]}
        """#.utf8)
        let decoded = TransferQueueSnapshot.decode(minimal)
        #expect(!decoded.lossy)
        let job = try #require(decoded.jobs.first)
        #expect(job.id == id)
        #expect(job.relativePath == "m.txt")
        #expect(job.state == .paused) // unknown state parks the job
        #expect(job.maxAttempts == 5)
        #expect(job.bytesTotal == 0)
    }

    @Test func newerSchemaIsLossy() {
        let data = Data(#"{"schemaVersion":99,"jobs":[]}"#.utf8)
        #expect(TransferQueueSnapshot.decode(data).lossy)
    }
}
