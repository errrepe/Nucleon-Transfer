// Nucleon Transfer — F8.2-R7 session robustness (Swift Testing).
// B12: the persisted upload queue is scoped to the signed-in account —
// other accounts' jobs are hidden and never run, legacy (owner-less) jobs
// are adopted by the first account, the snapshot stays schema 2. Also the
// 2FA failure policy (wrong code stays on the prompt) and ProtonUser.ID.
import Foundation
import Testing

@testable import NucleonTransfer

private func job(_ name: String, account: String? = nil) -> TransferJob {
    TransferJob(
        fileName: name, relativePath: name, localPath: "/tmp/\(name)",
        shareID: "S", parentLinkID: "P", bytesTotal: 10, accountID: account
    )
}

private func scopedQueue(
    _ scope: TransferAccountScope, store: (any TransferQueueStore)? = nil, box: ProgressBox? = nil
) async -> TransferQueue {
    let q = TransferQueue(store: store, accountScope: scope)
    await q.setSleeper { _ in }
    if let box { await q.setUploader(ChattyUploader(box: box)) }
    return q
}

private func quickBox() -> ProgressBox {
    let box = ProgressBox()
    box.steps = 1
    return box
}

/// Collects listener deliveries.
private actor Deliveries {
    var last: [TransferJob] = []
    func record(_ jobs: [TransferJob]) { last = jobs }
}

struct TransferQueueAccountScopeTests {
    @Test func enqueueStampsTheActiveAccount() async {
        let q = await scopedQueue(.account("A"))
        await q.enqueue(job("a.txt"))
        #expect(await q.snapshot().map(\.accountID) == ["A"])
    }

    @Test func explicitOwnerIsKept() async {
        let q = await scopedQueue(.account("A"))
        await q.enqueue(job("b.txt", account: "B"))
        #expect(await q.snapshot().isEmpty)
        #expect(await q.allJobs().map(\.accountID) == ["B"])
    }

    @Test func otherAccountsJobsAreHiddenAndNeverRun() async {
        let box = quickBox()
        let q = await scopedQueue(.account("A"), box: box)
        let foreign = job("b.txt", account: "B")
        let mine = job("a.txt", account: "A")
        await q.enqueueMany([foreign, mine])
        await waitForState(q, mine.id, .done)
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(box.order == ["a.txt"])
        #expect(await q.job(id: foreign.id)?.state == .queued)
        #expect(await q.snapshot().map(\.fileName) == ["a.txt"])
        #expect(await q.allJobs().count == 2)
    }

    @Test func switchingToTheOwnerRunsItsHeldJobs() async {
        let box = quickBox()
        let q = await scopedQueue(.account("A"), box: box)
        let foreign = job("b.txt", account: "B")
        await q.enqueue(foreign)
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(box.order.isEmpty)
        await q.setAccountScope(.account("B"))
        await waitForState(q, foreign.id, .done)
        #expect(box.order == ["b.txt"])
    }

    @Test func signedOutScopeShowsAndRunsNothing() async {
        let box = quickBox()
        let q = await scopedQueue(.signedOut, box: box)
        let j = job("a.txt", account: "A")
        await q.enqueue(j)
        await q.start()
        try? await Task.sleep(nanoseconds: 50_000_000)
        #expect(await q.snapshot().isEmpty)
        #expect(box.order.isEmpty)
        #expect(await q.job(id: j.id)?.state == .queued)
    }

    @Test func legacyJobsAreAdoptedByTheFirstAccountOnly() async {
        let q = await scopedQueue(.signedOut)
        let legacy = job("old.txt")
        await q.enqueue(legacy)
        #expect(await q.job(id: legacy.id)?.accountID == nil)
        await q.setAccountScope(.account("A"))
        #expect(await q.job(id: legacy.id)?.accountID == "A")
        #expect(await q.snapshot().map(\.id) == [legacy.id])
        await q.setAccountScope(.signedOut)
        await q.setAccountScope(.account("B"))
        #expect(await q.job(id: legacy.id)?.accountID == "A")
        #expect(await q.snapshot().isEmpty)
    }

    @Test func operatorsIgnoreOtherAccountsJobs() async {
        let q = await scopedQueue(.account("A"))
        let foreign = job("b.txt", account: "B")
        await q.enqueue(foreign)
        await q.cancel(id: foreign.id)
        await q.remove(id: foreign.id)
        await q.pauseAll()
        #expect(await q.job(id: foreign.id)?.state == .queued)
    }

    @Test func pauseAllOnlyTouchesTheActiveAccount() async {
        let q = await scopedQueue(.account("A"))
        let mine = job("a.txt", account: "A")
        let foreign = job("b.txt", account: "B")
        await q.enqueueMany([mine, foreign]) // no uploader: both stay queued
        await q.pauseAll()
        #expect(await q.job(id: mine.id)?.state == .paused)
        #expect(await q.job(id: foreign.id)?.state == .queued)
    }

    @Test func listenerOnlySeesTheActiveAccount() async {
        let q = await scopedQueue(.account("A"))
        let deliveries = Deliveries()
        await q.setListener { snap in Task { await deliveries.record(snap) } }
        await q.enqueueMany([job("a.txt", account: "A"), job("b.txt", account: "B")])
        try? await Task.sleep(nanoseconds: 200_000_000)
        #expect(await deliveries.last.map(\.fileName) == ["a.txt"])
    }

    @Test func accountIDPersistsAndSchemaStaysTwo() async throws {
        let store = CountingStore()
        let q = await scopedQueue(.account("A"), store: store)
        await q.enqueueMany([job("a.txt"), job("b.txt", account: "B")])
        await q.flush()
        let data = try #require(store.read())
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["schemaVersion"] as? Int == 2)
        let reloaded = TransferQueue(store: store, accountScope: .account("B"))
        #expect(await reloaded.snapshot().map(\.fileName) == ["b.txt"])
        #expect(Set(await reloaded.allJobs().compactMap(\.accountID)) == ["A", "B"])
    }

    @Test func preB12RecordDecodesWithoutOwner() throws {
        let json = """
        {"schemaVersion":2,"jobs":[{"id":"\(UUID().uuidString)","fileName":"x","localPath":"/tmp/x",
        "shareID":"S","parentLinkID":"P","state":"queued"}]}
        """
        let decoded = TransferQueueSnapshot.decode(Data(json.utf8))
        #expect(decoded.jobs.count == 1)
        #expect(decoded.jobs.first?.accountID == nil)
        #expect(!decoded.lossy)
    }

    @Test func scopeIncludesRule() {
        let a = job("a", account: "A")
        let legacy = job("l")
        #expect(TransferAccountScope.all.includes(a))
        #expect(TransferAccountScope.all.includes(legacy))
        #expect(TransferAccountScope.account("A").includes(a))
        #expect(!TransferAccountScope.account("B").includes(a))
        #expect(!TransferAccountScope.account("A").includes(legacy))
        #expect(!TransferAccountScope.signedOut.includes(a))
    }
}

struct TwoFactorFailureTests {
    @Test func wrongCodeIsRecoverable() {
        let wrong = ProtonAPIError.api(code: 8002, message: "Incorrect login credentials")
        #expect(TwoFactorFailure.isRecoverable(wrong))
        #expect(TwoFactorFailure.message(for: wrong).contains("code didn’t work"))
        let unprocessable = ProtonAPIError.http(status: 422, code: 8002, message: "bad")
        #expect(TwoFactorFailure.isRecoverable(unprocessable))
        #expect(TwoFactorFailure.message(for: unprocessable).contains("code didn’t work"))
    }

    @Test func networkBlipsAreRecoverable() {
        #expect(TwoFactorFailure.isRecoverable(ProtonAPIError.transport(URLError(.timedOut))))
        #expect(TwoFactorFailure.isRecoverable(URLError(.notConnectedToInternet)))
        #expect(TwoFactorFailure.isRecoverable(ProtonAPIError.http(status: 503, code: nil, message: "x")))
        let timeout = ProtonAPIError.http(status: 408, code: nil, message: "x")
        #expect(TwoFactorFailure.isRecoverable(timeout))
        #expect(!TwoFactorFailure.message(for: timeout).contains("code didn’t work"))
    }

    @Test func sessionLossAndRateLimitsAreNot() {
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.unauthorized))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.rateLimited))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.humanVerificationRequired))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.http(status: 429, code: nil, message: "x")))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.http(status: 401, code: nil, message: "x")))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.http(status: 422, code: 2028, message: "x")))
        #expect(!TwoFactorFailure.isRecoverable(ProtonAPIError.keyVerificationFailed))
    }
}

struct ProtonUserIDTests {
    @Test func decodesUserID() throws {
        let json = #"{"User":{"ID":"uid-123","Keys":[]}}"#
        let res = try JSONDecoder().decode(ProtonUserResponse.self, from: Data(json.utf8))
        #expect(res.user.id == "uid-123")
    }

    @Test func missingIDDecodesAsNil() throws {
        let json = #"{"User":{"Keys":[]}}"#
        let res = try JSONDecoder().decode(ProtonUserResponse.self, from: Data(json.utf8))
        #expect(res.user.id == nil)
    }
}
