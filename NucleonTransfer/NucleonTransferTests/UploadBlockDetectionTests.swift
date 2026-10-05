// Nucleon Transfer — F8.4-U1 "uploads blocked" detection (Swift Testing).
// The Proton code survives classification as a typed field on the job,
// and only NEW 2000 failures (not ones restored from disk) flip the flag.
import Foundation
import Testing

@testable import NucleonTransfer

private func failedJob(code: Int?, id: UUID = UUID()) -> TransferJob {
    var job = makeJob()
    job.id = id
    job.state = .failed
    job.errorCode = code
    return job
}

struct UploadBlockDetectionTests {
    @Test func protonCodeLooksThroughEveryShape() {
        #expect(TransferErrorClassify.protonCode(ProtonAPIError.api(code: 2000, message: "x")) == 2000)
        #expect(TransferErrorClassify.protonCode(
            ProtonAPIError.http(status: 422, code: 2000, message: "x")
        ) == 2000)
        #expect(TransferErrorClassify.protonCode(
            ProtonAPIError.transport(ProtonAPIError.api(code: 2000, message: "x"))
        ) == 2000)
        #expect(TransferErrorClassify.protonCode(ProtonAPIError.http(status: 500, code: nil, message: "x")) == nil)
        #expect(TransferErrorClassify.protonCode(URLError(.timedOut)) == nil)
        #expect(TransferErrorClassify.protonCode(TransferFailure.permanent("api 2000: x")) == nil)
    }

    @Test func queueRecordsTheTypedCodeOnPermanentFailure() async {
        let box = MockBox()
        box.script = [.failure(ProtonAPIError.http(status: 422, code: 2000, message: "outdated"))]
        let (q, _) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        let jobs = await q.snapshot()
        #expect(jobs[0].state == .failed)
        #expect(jobs[0].errorCode == 2000)
        #expect(UploadBlockDetection.isNotAllowlisted(jobs[0]))
    }

    @Test func relaunchClearsTheCode() async {
        let box = MockBox()
        box.script = [.failure(ProtonAPIError.api(code: 2000, message: "outdated"))]
        let (q, _) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        let id = await q.snapshot()[0].id
        await q.relaunch(id: id)
        await drain(q)
        let job = await q.snapshot()[0]
        #expect(job.state == .done)
        #expect(job.errorCode == nil)
    }

    @Test func codeRoundTripsAndOldSnapshotsDecode() throws {
        let job = failedJob(code: 2000)
        let data = try JSONEncoder().encode(job)
        #expect(try JSONDecoder().decode(TransferJob.self, from: data).errorCode == 2000)

        // A snapshot written before U1 has no errorCode key.
        var dict = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        dict["errorCode"] = nil
        let legacy = try JSONSerialization.data(withJSONObject: dict)
        #expect(try JSONDecoder().decode(TransferJob.self, from: legacy).errorCode == nil)
    }

    @Test func newAllowlistFailureBlocks() {
        let result = UploadBlockDetection.scan([failedJob(code: 2000)], knownFailed: [])
        #expect(result.blocked)
        #expect(result.failed.count == 1)
    }

    @Test func otherFailuresDoNotBlock() {
        var queued = makeJob()
        queued.errorCode = 2000 // not failed (e.g. mid-retry) — ignored
        let result = UploadBlockDetection.scan(
            [failedJob(code: 2501), failedJob(code: nil), queued],
            knownFailed: []
        )
        #expect(!result.blocked)
        #expect(result.failed.count == 2)
    }

    @Test func failuresAlreadyKnownDoNotBlock() {
        // Restored from disk at launch: seeded into knownFailed.
        let old = failedJob(code: 2000)
        let result = UploadBlockDetection.scan([old], knownFailed: [old.id])
        #expect(!result.blocked)
        #expect(result.failed == [old.id])
    }

    @Test func retriedJobFailingAgainIsNew() {
        let id = UUID()
        var retried = failedJob(code: 2000, id: id)
        retried.state = .uploading
        let mid = UploadBlockDetection.scan([retried], knownFailed: [id])
        #expect(mid.failed.isEmpty)
        let again = UploadBlockDetection.scan([failedJob(code: 2000, id: id)], knownFailed: mid.failed)
        #expect(again.blocked)
    }
}
