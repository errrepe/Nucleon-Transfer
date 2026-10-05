// Nucleon Transfer — F8.2 review fixes (Swift Testing): sign-out suspends
// uploads without user-pausing them, cancelled/removed jobs' drafts are
// discarded in a detached task, a lost commit response is verified instead
// of failing the job, and atomicWrite never retries a refused name.
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - fakes

/// Uploader that creates a draft, optionally announces the commit, then
/// works until cancelled (or finishes after `workNanoseconds`).
final class DraftLifecycleBox: @unchecked Sendable {
    private let lock = NSLock()
    var workNanoseconds: UInt64 = 5_000_000_000
    var sendCommit = false
    /// Scripted results per attempt (consumed first); default = work.
    var script: [Result<String?, any Error>] = []
    var discardError: (any Error)?
    private(set) var seen: [TransferJob] = []
    private(set) var discarded: [TransferJob] = []

    func next(_ job: TransferJob) -> (Int, Result<String?, any Error>?) {
        lock.withLock {
            seen.append(job)
            return (seen.count - 1, script.isEmpty ? nil : script.removeFirst())
        }
    }

    func discard(_ job: TransferJob) throws {
        try lock.withLock {
            discarded.append(job)
            if let discardError { throw discardError }
        }
    }

    var jobs: [TransferJob] { lock.withLock { seen } }
    var discards: [TransferJob] { lock.withLock { discarded } }
}

struct DraftLifecycleUploader: TransferUploader {
    let box: DraftLifecycleBox

    func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
        try await upload(job: job, progress: progress, events: TransferUploadEvents())
    }

    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void,
        events: TransferUploadEvents
    ) async throws -> String? {
        let (attempt, scripted) = box.next(job)
        await events.draftCreated("DRAFT-\(attempt)", "REV-\(attempt)")
        if box.sendCommit { await events.commitSending() }
        if let scripted {
            switch scripted {
            case let .success(id): return id
            case let .failure(e): throw e
            }
        }
        do {
            try await Task.sleep(nanoseconds: box.workNanoseconds)
        } catch {
            throw ProtonAPIError.transport(URLError(.cancelled))
        }
        return "L-\(job.fileName)"
    }

    func discardDraft(job: TransferJob) async throws {
        // Detached from the cancelled run: must not see its cancellation.
        #expect(!Task.isCancelled)
        try box.discard(job)
    }
}

private func lifecycleQueue(
    _ box: DraftLifecycleBox, scope: TransferAccountScope = .all
) async -> TransferQueue {
    let q = TransferQueue(store: nil, accountScope: scope)
    await q.setSleeper { _ in }
    await q.setUploader(DraftLifecycleUploader(box: box))
    return q
}

private func waitUntil(timeout: Double = 5, _ condition: () async -> Bool) async {
    let start = Date()
    while !(await condition()), Date().timeIntervalSince(start) < timeout {
        try? await Task.sleep(nanoseconds: 2_000_000)
    }
}

private func link(
    id: String = "D1", parent: String = "P", state: Int, activeRevision: String?
) throws -> DriveLink {
    var json: [String: Any] = [
        "LinkID": id, "ParentLinkID": parent, "Type": 2, "Name": "n", "Size": 1,
        "State": state, "CreateTime": 0, "ModifyTime": 0,
    ]
    if let activeRevision {
        json["FileProperties"] = ["ActiveRevision": ["ID": activeRevision]]
    }
    return try JSONDecoder().decode(DriveLink.self, from: JSONSerialization.data(withJSONObject: json))
}

private func committedJob(commitSent: Bool = true) -> TransferJob {
    var j = makeJob()
    j.draftLinkID = "D1"
    j.draftRevisionID = "R1"
    j.draftCommitSent = commitSent
    return j
}

private final class Calls: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.withLock { items.append(s) } }
    var all: [String] { lock.withLock { items } }
}

struct TransferReviewFixesTests {
    // MARK: 1. sign-out suspends without user-pausing

    @Test func signOutKeepsRunningAndQueuedJobsQueuedForTheOwner() async {
        let box = DraftLifecycleBox()
        let q = TransferQueue(store: nil, maxConcurrentUploads: 1, accountScope: .account("A"))
        await q.setSleeper { _ in }
        await q.setUploader(DraftLifecycleUploader(box: box))
        let running = makeJob("run.txt")
        let waiting = makeJob("wait.txt")
        await q.enqueueMany([running, waiting])
        await waitForState(q, running.id, .uploading)

        await q.suspendForSignOut()
        await q.setAccountScope(.signedOut)
        // The cancelled run unwinds without parking/failing the job.
        await waitUntil { box.jobs.count == 1 }
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(await q.job(id: running.id)?.state == .queued)
        #expect(await q.job(id: waiting.id)?.state == .queued)
        #expect(await q.snapshot().isEmpty)

        // Same account signs back in: both continue on their own.
        box.workNanoseconds = 1_000_000
        await q.setUploader(DraftLifecycleUploader(box: box))
        await q.setAccountScope(.account("A"))
        await waitForState(q, running.id, .done)
        await waitForState(q, waiting.id, .done)
        #expect(await q.job(id: running.id)?.state == .done)
        #expect(await q.job(id: waiting.id)?.state == .done)
    }

    @Test func suspendedJobsDoNotRunForAnotherAccount() async {
        let box = DraftLifecycleBox()
        let q = await lifecycleQueue(box, scope: .account("A"))
        let j = makeJob()
        await q.enqueue(j)
        await waitForState(q, j.id, .uploading)
        await q.suspendForSignOut()
        await q.setAccountScope(.signedOut)
        box.workNanoseconds = 1_000_000
        await q.setUploader(DraftLifecycleUploader(box: box))
        await q.setAccountScope(.account("B"))
        try? await Task.sleep(nanoseconds: 100_000_000)
        #expect(box.jobs.count == 1)
        #expect(await q.job(id: j.id)?.state == .queued)
    }

    // MARK: 2. drafts of cancelled / removed jobs are discarded

    @Test func cancelMidUploadDiscardsTheDraftDetached() async {
        let box = DraftLifecycleBox()
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await waitUntil { await q.job(id: j.id)?.draftLinkID != nil }
        await q.cancel(id: j.id)
        await waitUntil { !box.discards.isEmpty }
        await q.waitForDraftCleanups()
        #expect(box.discards.map(\.draftLinkID) == ["DRAFT-0"])
        let after = await q.job(id: j.id)
        #expect(after?.state == .cancelled)
        #expect(after?.draftLinkID == nil) // cleared on success
    }

    @Test func removeMidUploadDiscardsTheDraft() async {
        let box = DraftLifecycleBox()
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await waitUntil { await q.job(id: j.id)?.draftLinkID != nil }
        await q.remove(id: j.id)
        await waitUntil { !box.discards.isEmpty }
        await q.waitForDraftCleanups()
        #expect(box.discards.map(\.draftLinkID) == ["DRAFT-0"])
        #expect(await q.job(id: j.id) == nil)
    }

    @Test func cancellingAnIdleFailedJobDiscardsItsDraftAtOnce() async {
        let box = DraftLifecycleBox()
        box.script = [.failure(TransferFailure.permanent("nope"))]
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await waitForState(q, j.id, .failed)
        #expect(await q.job(id: j.id)?.draftLinkID == "DRAFT-0")
        await q.cancel(id: j.id)
        await q.waitForDraftCleanups()
        #expect(box.discards.map(\.draftLinkID) == ["DRAFT-0"])
        #expect(await q.job(id: j.id)?.draftLinkID == nil)
    }

    @Test func failedDiscardKeepsTheDraftForTheNextAttempt() async {
        let box = DraftLifecycleBox()
        box.script = [.failure(TransferFailure.permanent("nope"))]
        box.discardError = URLError(.timedOut)
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await waitForState(q, j.id, .failed)
        await q.cancel(id: j.id)
        await q.waitForDraftCleanups()
        #expect(box.discards.count == 1)
        #expect(await q.job(id: j.id)?.draftLinkID == "DRAFT-0")
    }

    @Test func pauseDoesNotDiscardTheDraft() async {
        let box = DraftLifecycleBox()
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await waitUntil { await q.job(id: j.id)?.draftLinkID != nil }
        await q.pause(id: j.id)
        try? await Task.sleep(nanoseconds: 100_000_000)
        await q.waitForDraftCleanups()
        #expect(box.discards.isEmpty)
    }

    // MARK: 3. lost commit response

    @Test func commitSentIsPersistedAndCarriedIntoTheRetry() async {
        let box = DraftLifecycleBox()
        box.sendCommit = true
        box.script = [.failure(TransferFailure.transient("timeout")), .success("L-ok")]
        let q = await lifecycleQueue(box)
        let j = makeJob()
        await q.enqueue(j)
        await drain(q)
        let seen = box.jobs
        #expect(seen.count == 2)
        #expect(seen[0].draftCommitSent == false)
        #expect(seen[1].draftCommitSent == true)
        #expect(seen[1].draftLinkID == "DRAFT-0")
        #expect(seen[1].draftRevisionID == "REV-0")
        let done = await q.job(id: j.id)
        #expect(done?.state == .done)
        #expect(done?.remoteLinkID == "L-ok")
        #expect(done?.draftCommitSent == false)
    }

    @Test func newDraftResetsCommitSent() async {
        let box = DraftLifecycleBox()
        box.script = [.failure(TransferFailure.transient("t")), .success("x")]
        let q = await lifecycleQueue(box)
        var j = makeJob()
        j.draftLinkID = "OLD"
        j.draftCommitSent = true
        await q.enqueue(j)
        await drain(q)
        #expect(box.jobs[1].draftLinkID == "DRAFT-0")
        #expect(box.jobs[1].draftCommitSent == false)
    }

    @Test func committedPredicateMatchesTheSDK() throws {
        let ok = try link(state: 1, activeRevision: "R1")
        #expect(UploadCommitVerification.isCommitted(ok, revisionID: "R1", parentLinkID: "P"))
        #expect(!UploadCommitVerification.isCommitted(ok, revisionID: "R2", parentLinkID: "P"))
        #expect(!UploadCommitVerification.isCommitted(ok, revisionID: "R1", parentLinkID: "OTHER"))
        let draft = try link(state: 0, activeRevision: "R1")
        #expect(!UploadCommitVerification.isCommitted(draft, revisionID: "R1", parentLinkID: "P"))
        let noRevision = try link(state: 1, activeRevision: nil)
        #expect(!UploadCommitVerification.isCommitted(noRevision, revisionID: "R1", parentLinkID: "P"))
    }

    @Test func failedCommitThatLandedCountsAsCommitted() async {
        let lost = await UploadCommitVerification.commit(
            send: { throw URLError(.timedOut) },
            isCommitted: { true }
        )
        guard case .committed = lost else { Issue.record("expected committed"); return }

        let rejected = await UploadCommitVerification.commit(
            send: { throw ProtonAPIError.api(code: 2000, message: "bad") },
            isCommitted: { false }
        )
        guard case let .notCommitted(e) = rejected else { Issue.record("expected notCommitted"); return }
        #expect((e as? ProtonAPIError) == .api(code: 2000, message: "bad"))

        let unknown = await UploadCommitVerification.commit(
            send: { throw URLError(.timedOut) },
            isCommitted: { throw URLError(.notConnectedToInternet) }
        )
        guard case let .unknown(original) = unknown else { Issue.record("expected unknown"); return }
        #expect((original as? URLError)?.code == .timedOut) // the commit's error, not the check's

        let fine = await UploadCommitVerification.commit(send: {}, isCommitted: { false })
        guard case .committed = fine else { Issue.record("expected committed"); return }
    }

    @Test func retryPreCheckReturnsTheCommittedLink() async throws {
        let active = try link(state: 1, activeRevision: "R1")
        let found = await UploadCommitVerification.alreadyCommitted(
            job: committedJob(), getLink: { _ in active }
        )
        #expect(found == "D1")
        // Commit never sent → no lookup at all.
        let calls = Calls()
        let none = await UploadCommitVerification.alreadyCommitted(
            job: committedJob(commitSent: false),
            getLink: { id in calls.add(id); return active }
        )
        #expect(none == nil)
        #expect(calls.all.isEmpty)
        // Still a draft, or lookup failed → upload again.
        let draft = try link(state: 0, activeRevision: nil)
        #expect(await UploadCommitVerification.alreadyCommitted(job: committedJob(), getLink: { _ in draft }) == nil)
        #expect(await UploadCommitVerification.alreadyCommitted(
            job: committedJob(), getLink: { _ in throw URLError(.timedOut) }) == nil)
    }

    @Test func discardNeverDeletesACommittedRevision() async throws {
        let deletes = Calls()
        let lookups = Calls()
        // No commit sent: delete straight away, no lookup.
        try await UploadCommitVerification.discardDraft(
            job: committedJob(commitSent: false),
            getLink: { id in lookups.add(id); return try link(state: 1, activeRevision: "R1") },
            delete: { deletes.add($0) }
        )
        #expect(deletes.all == ["D1"])
        #expect(lookups.all.isEmpty)
        // Commit sent and the link is active: keep it.
        try await UploadCommitVerification.discardDraft(
            job: committedJob(),
            getLink: { _ in try link(state: 1, activeRevision: "R1") },
            delete: { deletes.add($0) }
        )
        #expect(deletes.all == ["D1"])
        // Commit sent but still a draft: delete.
        try await UploadCommitVerification.discardDraft(
            job: committedJob(),
            getLink: { _ in try link(state: 0, activeRevision: nil) },
            delete: { deletes.add($0) }
        )
        #expect(deletes.all == ["D1", "D1"])
    }

    @Test func commitSentRoundTripsAndDefaultsToFalse() throws {
        let j = committedJob()
        let decoded = try JSONDecoder().decode(TransferJob.self, from: JSONEncoder().encode(j))
        #expect(decoded.draftCommitSent)
        let legacy = #"{"id":"\#(UUID().uuidString)","fileName":"a","localPath":"/a","shareID":"S","parentLinkID":"P"}"#
        let old = try JSONDecoder().decode(TransferJob.self, from: Data(legacy.utf8))
        #expect(old.draftCommitSent == false)
    }

    // MARK: 5. atomicWrite naming

    @Test func danglingSymlinkIsNeverOverwrittenNorRetriedForever() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nt-review-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("a.txt")
        try FileManager.default.createSymbolicLink(
            atPath: target.path, withDestinationPath: dir.appendingPathComponent("missing").path
        )
        #expect(!FileManager.default.fileExists(atPath: target.path)) // follows the link
        #expect(FileDownload.itemExists(at: target))                   // lstat semantics
        #expect(FileDownload.uniqueDestination(in: dir, name: "a.txt").lastPathComponent == "a (1).txt")
        let written = try FileDownload.atomicWrite(Data("x".utf8), to: target)
        #expect(written.lastPathComponent == "a (1).txt")
        #expect((try? FileManager.default.destinationOfSymbolicLink(atPath: target.path)) != nil)
    }

    @Test func eachRefusedMoveTriesADifferentName() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nt-review-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let tried = Calls()
        // Refuses the first two names although nothing is on disk (an
        // item the existence probe cannot see).
        let written = try FileDownload.atomicWrite(Data("x".utf8), to: dir.appendingPathComponent("b.txt")) { src, dst in
            tried.add(dst.lastPathComponent)
            if tried.all.count <= 2 { return false }
            return try FileDownload.moveExclusive(src, to: dst)
        }
        #expect(tried.all == ["b.txt", "b (1).txt", "b (2).txt"])
        #expect(written.lastPathComponent == "b (2).txt")
    }
}
