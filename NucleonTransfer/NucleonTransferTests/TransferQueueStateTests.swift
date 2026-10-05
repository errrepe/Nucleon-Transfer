// Nucleon Transfer — F8.2-R1 queue state correctness (Swift Testing).
// Pause/resume must never run a job twice, operator stops never surface as
// failures, and a removed-but-still-unwinding upload keeps its slot.
import Foundation
import Testing

@testable import NucleonTransfer

/// Slow uploader with a "commit" counter. `honoursCancellation == false`
/// models an uploader that only notices cancellation after its in-flight
/// request finished (the real DriveClient path between two awaits).
final class SlowCommitBox: @unchecked Sendable {
    private let lock = NSLock()
    var workNanoseconds: UInt64 = 200_000_000
    var honoursCancellation = true
    /// Thrown when cancellation is noticed (default: what APIClient throws).
    var cancellationError: any Error = ProtonAPIError.transport(URLError(.cancelled))
    private(set) var commits = 0
    private(set) var calls = 0
    private(set) var concurrent = 0
    private(set) var maxSeen = 0

    func enter() {
        lock.withLock {
            calls += 1
            concurrent += 1
            maxSeen = max(maxSeen, concurrent)
        }
    }

    func leave() { lock.withLock { concurrent -= 1 } }
    func commit() { lock.withLock { commits += 1 } }
}

struct SlowCommitUploader: TransferUploader {
    let box: SlowCommitBox

    func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
        box.enter()
        defer { box.leave() }
        if box.honoursCancellation {
            do {
                try await Task.sleep(nanoseconds: box.workNanoseconds)
            } catch {
                throw box.cancellationError
            }
        } else {
            await uncancellableSleep(box.workNanoseconds)
        }
        box.commit()
        await progress(job.bytesTotal)
        return "link-\(job.fileName)"
    }
}

/// Sleep that ignores Task cancellation (a request already on the wire).
func uncancellableSleep(_ ns: UInt64) async {
    await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
        DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(Int(ns))) { c.resume() }
    }
}

func waitForState(_ q: TransferQueue, _ id: UUID, _ state: TransferJobState, timeout: Double = 5) async {
    let start = Date()
    while await q.job(id: id)?.state != state, Date().timeIntervalSince(start) < timeout {
        try? await Task.sleep(nanoseconds: 2_000_000)
    }
}

func makeSlowQueue(_ box: SlowCommitBox, maxConcurrent: Int = 3) async -> TransferQueue {
    let q = TransferQueue(storeURL: nil, maxConcurrentUploads: maxConcurrent)
    await q.setUploader(SlowCommitUploader(box: box))
    await q.setSleeper { _ in }
    return q
}

struct TransferQueueStateTests {
    // MARK: pause → resume runs the job exactly once

    @Test func pauseResumeWithUploaderIgnoringCancellationCommitsOnce() async {
        let box = SlowCommitBox()
        box.honoursCancellation = false
        box.workNanoseconds = 300_000_000
        let q = await makeSlowQueue(box)
        let job = makeJob()
        await q.enqueue(job)
        await waitForState(q, job.id, .uploading)
        await q.pause(id: job.id)
        await q.resume(id: job.id) // old run still in flight
        await drain(q)
        // Let any (wrong) second run finish too before asserting.
        try? await Task.sleep(nanoseconds: 400_000_000)
        #expect(await q.job(id: job.id)?.state == .done)
        #expect(box.commits == 1)
        #expect(box.calls == 1)
    }

    @Test func pauseResumeWithCancellableUploaderCommitsOnce() async {
        let box = SlowCommitBox()
        let q = await makeSlowQueue(box)
        let job = makeJob()
        await q.enqueue(job)
        await waitForState(q, job.id, .uploading)
        await q.pause(id: job.id)
        await q.resume(id: job.id)
        await drain(q)
        let final = await q.job(id: job.id)
        #expect(final?.state == .done)
        #expect(final?.errorMessage == nil)
        #expect(box.commits == 1)
        #expect(box.maxSeen == 1) // never two runs of the same job at once
    }

    // MARK: operator stops are never failures

    @Test func pauseNeverProducesFailed() async {
        let box = SlowCommitBox()
        let q = await makeSlowQueue(box)
        let job = makeJob()
        await q.enqueue(job)
        await waitForState(q, job.id, .uploading)
        await q.pause(id: job.id)
        try? await Task.sleep(nanoseconds: 50_000_000)
        let j = await q.job(id: job.id)
        #expect(j?.state == .paused)
        #expect(j?.errorMessage == nil)
        #expect(j?.attempt == 0)
    }

    @Test func cancelNeverProducesFailed() async {
        let box = SlowCommitBox()
        let q = await makeSlowQueue(box)
        let job = makeJob()
        await q.enqueue(job)
        await waitForState(q, job.id, .uploading)
        await q.cancel(id: job.id)
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(await q.job(id: job.id)?.state == .cancelled)
    }

    @Test func pauseAllNeverProducesFailed() async {
        let box = SlowCommitBox()
        // Even a non-cancellation error after the stop must be ignored.
        box.cancellationError = ProtonAPIError.api(code: 400, message: "aborted")
        let q = await makeSlowQueue(box)
        let jobs = (0..<3).map { makeJob("f\($0).txt") }
        await q.enqueueMany(jobs)
        for j in jobs { await waitForState(q, j.id, .uploading) }
        await q.pauseAll()
        try? await Task.sleep(nanoseconds: 50_000_000)
        let snap = await q.snapshot()
        #expect(snap.allSatisfy { $0.state == .paused })
        #expect(snap.allSatisfy { $0.errorMessage == nil })
    }

    @Test func retryAllDoesNotRestartCancelled() async {
        let box = SlowCommitBox()
        let q = await makeSlowQueue(box)
        let job = makeJob()
        await q.enqueue(job)
        await waitForState(q, job.id, .uploading)
        await q.cancel(id: job.id)
        try? await Task.sleep(nanoseconds: 50_000_000)
        await q.relaunchAllFailed()
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(await q.job(id: job.id)?.state == .cancelled)
        #expect(box.commits == 0)
    }

    // MARK: remove keeps the slot until the run unwinds

    @Test func removeRunningJobDoesNotExceedLimit() async {
        let box = SlowCommitBox()
        box.honoursCancellation = false
        box.workNanoseconds = 300_000_000
        let q = await makeSlowQueue(box, maxConcurrent: 1)
        let a = makeJob("a.txt")
        let b = makeJob("b.txt")
        await q.enqueueMany([a, b])
        await waitForState(q, a.id, .uploading)
        await q.remove(id: a.id)
        // b must not start while a's upload is still on the wire.
        #expect(await q.job(id: b.id)?.state == .queued)
        await drain(q)
        #expect(await q.job(id: a.id) == nil)
        #expect(await q.job(id: b.id)?.state == .done)
        #expect(box.maxSeen == 1)
    }

    // MARK: classification

    @Test func cancellationShapesClassifyAsCancelled() {
        #expect(TransferErrorClassify.classify(CancellationError()) == .cancelled)
        #expect(TransferErrorClassify.classify(URLError(.cancelled)) == .cancelled)
        #expect(TransferErrorClassify.classify(ProtonAPIError.transport(URLError(.cancelled))) == .cancelled)
        #expect(TransferErrorClassify.classify(ProtonAPIError.transport(CancellationError())) == .cancelled)
        #expect(!TransferErrorClassify.isCancellation(URLError(.timedOut)))
    }
}
