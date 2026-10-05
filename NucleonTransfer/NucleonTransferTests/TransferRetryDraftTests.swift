// Nucleon Transfer — F8.2-R3 retry classification + stale-draft recovery
// (Swift Testing). Fakes only: no network, no real backoff.
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - draft API fake

final class FakeDraftAPI: FileDraftAPI, @unchecked Sendable {
    private let lock = NSLock()
    /// Pending drafts the server currently holds for the probed hash.
    var pending: [PendingHash] = []
    /// Per-probe overrides (consumed first): models a draft appearing
    /// between the probe and the create.
    var probeResults: [[PendingHash]] = []
    /// Scripted create results (default: success).
    var createScript: [Result<(String, String), any Error>] = []
    private(set) var deleted: [String] = []
    private(set) var creates: [CreateFileRequest] = []
    private(set) var probes = 0

    func checkAvailableHashes(
        shareID: String, parentLinkID: String, hashes: [String]
    ) async throws -> (available: [String], pending: [PendingHash]) {
        lock.withLock {
            probes += 1
            if !probeResults.isEmpty { pending = probeResults.removeFirst() }
            return (pending.isEmpty ? hashes : [], pending)
        }
    }

    func createFileDraft(
        shareID: String, request: CreateFileRequest
    ) async throws -> (linkID: String, revisionID: String) {
        let next: Result<(String, String), any Error> = lock.withLock {
            creates.append(request)
            return createScript.isEmpty ? .success(("NEW", "REV")) : createScript.removeFirst()
        }
        switch next {
        case let .success((l, r)): return (l, r)
        case let .failure(e): throw e
        }
    }

    func deleteDraft(shareID: String, parentLinkID: String, linkID: String) async throws {
        lock.withLock {
            deleted.append(linkID)
            pending.removeAll { $0.linkID == linkID }
        }
    }
}

private func draftRequest(hash: String = "abc", clientUID: String? = "CU-1") -> CreateFileRequest {
    CreateFileRequest(
        parentLinkID: "P", name: "n", hash: hash, mimeType: "text/plain",
        contentKeyPacket: "k", contentKeyPacketSignature: "s", nodeKey: "nk",
        nodePassphrase: "np", nodePassphraseSignature: "nps",
        signatureAddress: "a@b", signatureEmail: "a@b", clientUID: clientUID
    )
}

private func pendingDraft(_ linkID: String, hash: String = "abc", clientUID: String?) -> PendingHash {
    PendingHash(hash: hash, revisionID: "R-\(linkID)", linkID: linkID, clientUID: clientUID)
}

private let duplicate = ProtonAPIError.api(code: 2500, message: "A file or folder with that name already exists")

// MARK: - queue uploader fake that records events/jobs

final class DraftAwareBox: @unchecked Sendable {
    private let lock = NSLock()
    var script: [Result<String?, any Error>] = []
    private(set) var seenJobs: [TransferJob] = []

    func record(_ job: TransferJob) -> Result<String?, any Error>? {
        lock.withLock {
            seenJobs.append(job)
            return script.isEmpty ? nil : script.removeFirst()
        }
    }

    var jobs: [TransferJob] { lock.withLock { seenJobs } }
}

struct DraftAwareUploader: TransferUploader {
    let box: DraftAwareBox

    func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
        try await upload(job: job, progress: progress, events: TransferUploadEvents())
    }

    func upload(
        job: TransferJob,
        progress: @Sendable (Int64) async -> Void,
        events: TransferUploadEvents
    ) async throws -> String? {
        let attempt = box.jobs.count
        await events.draftCreated("DRAFT-\(attempt)", "REV-\(attempt)")
        switch box.record(job) ?? .success("L-\(job.fileName)") {
        case let .success(id): return id
        case let .failure(e): throw e
        }
    }
}

struct TransferRetryDraftTests {
    // MARK: classification on HTTP status

    @Test func httpStatusDrivesClassification() {
        func c(_ status: Int, _ code: Int? = nil) -> TransferFailure {
            TransferErrorClassify.classify(ProtonAPIError.http(status: status, code: code, message: "m"))
        }
        #expect(c(503) == .transient("http 503: m"))
        #expect(c(500) == .transient("http 500: m"))
        #expect(c(429, 2028) == .transient("http 429: m"))
        #expect(c(408) == .transient("http 408: m"))
        #expect(c(400) == .permanent("http 400: m"))
        #expect(c(422, 2500) == .permanent("http 422: m"))
        #expect(c(302) == .permanent("http 302: m"))
        // Wrapped in transport still classifies by the inner error.
        let wrapped = ProtonAPIError.transport(ProtonAPIError.http(status: 502, code: nil, message: "m"))
        #expect(TransferErrorClassify.classify(wrapped) == .transient("http 502: m"))
    }

    @Test func retryAfterRaisesTheBackoffButIsCapped() {
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1, retryAfter: 30) == 30_000_000_000)
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 7, retryAfter: 2) == 60_000_000_000) // backoff larger
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1, retryAfter: 100_000) == 300_000_000_000) // capped
        #expect(TransferRetryPolicy.delayNanoseconds(failures: 1, jitter: 7, retryAfter: 30) == 30_000_000_007)
    }

    // MARK: queue retries

    @Test func http503ThenSuccessIsRetried() async {
        let box = MockBox()
        box.script = [.failure(ProtonAPIError.http(status: 503, code: nil, message: "storage HTTP 503"))]
        let (q, sleeper) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        let job = await q.snapshot()[0]
        #expect(job.state == .done)
        #expect(job.attempt == 1)
        #expect(box.calls == 2)
        #expect(await sleeper.waits.count == 1)
    }

    @Test func http429RetryAfterIsHonoured() async {
        let box = MockBox()
        box.script = [.failure(ProtonAPIError.transport(
            ProtonAPIError.http(status: 429, code: nil, message: "slow", retryAfter: 42)))]
        let (q, sleeper) = await makeQueue(box: box)
        await q.enqueue(makeJob())
        await drain(q)
        #expect(await q.snapshot()[0].state == .done)
        let waits = await sleeper.waits
        #expect(waits.count == 1)
        #expect(waits[0] >= 42_000_000_000 && waits[0] <= 43_000_000_000)
    }

    // MARK: draft IDs + ClientUID persisted by the queue

    @Test func queuePersistsDraftAndReusesItOnRetry() async {
        let box = DraftAwareBox()
        box.script = [.failure(TransferFailure.transient("blocks failed"))]
        let q = TransferQueue(storeURL: nil)
        await q.setUploader(DraftAwareUploader(box: box))
        await q.setSleeper { _ in }
        let job = makeJob()
        await q.enqueue(job)
        await drain(q)
        let seen = box.jobs
        #expect(seen.count == 2)
        #expect(seen[0].clientUID != nil)
        #expect(seen[0].clientUID == seen[1].clientUID) // stable across attempts
        #expect(seen[0].draftLinkID == nil)
        #expect(seen[1].draftLinkID == "DRAFT-0") // retry knows the stale draft
        let done = await q.job(id: job.id)
        #expect(done?.state == .done)
        #expect(done?.draftLinkID == nil) // cleared on success
    }

    @Test func legacyJobWithoutClientUIDGetsOne() async throws {
        var legacy = makeJob()
        legacy.clientUID = nil
        let store = CountingStore(initial: try JSONEncoder().encode([legacy]))
        let box = DraftAwareBox()
        let q = TransferQueue(store: store)
        await q.setUploader(DraftAwareUploader(box: box))
        await q.start()
        await drain(q)
        #expect(box.jobs.first?.clientUID?.isEmpty == false)
    }

    // MARK: FileDraftFlow

    @Test func ownStaleDraftIsDeletedBeforeCreate() async throws {
        let api = FakeDraftAPI()
        api.pending = [pendingDraft("OLD", clientUID: "CU-1")]
        let ids = try await FileDraftFlow.createDraft(
            api: api, shareID: "S", request: draftRequest(), knownDraftLinkID: nil
        )
        #expect(ids.linkID == "NEW")
        #expect(api.deleted == ["OLD"])
        #expect(api.creates.count == 1)
        #expect(api.creates[0].clientUID == "CU-1")
    }

    @Test func retryAfterDraftExistsDeletesItInsteadOfFailingWith2500() async throws {
        // The probe saw nothing (draft appeared in between), the create
        // answers 2500, the second probe lists our draft → delete → create.
        let api = FakeDraftAPI()
        api.createScript = [.failure(duplicate)]
        api.probeResults = [[], [pendingDraft("RACE", clientUID: "CU-1")]]
        let ids = try await FileDraftFlow.createDraft(
            api: api, shareID: "S", request: draftRequest(), knownDraftLinkID: nil
        )
        #expect(ids.linkID == "NEW")
        #expect(api.deleted == ["RACE"])
        #expect(api.creates.count == 2)
    }

    @Test func persistedDraftLinkMatchesEvenWithoutClientUID() async throws {
        // Drafts made before ClientUID was sent come back as ClientUID:null.
        let api = FakeDraftAPI()
        api.pending = [pendingDraft("LEGACY", clientUID: nil)]
        _ = try await FileDraftFlow.createDraft(
            api: api, shareID: "S", request: draftRequest(), knownDraftLinkID: "LEGACY"
        )
        #expect(api.deleted == ["LEGACY"])
    }

    @Test func otherClientsDraftIsNeverDeleted() async {
        let api = FakeDraftAPI()
        api.pending = [pendingDraft("THEIRS", clientUID: "SOMEONE-ELSE")]
        api.createScript = [.failure(duplicate)]
        await #expect(throws: duplicate) {
            _ = try await FileDraftFlow.createDraft(
                api: api, shareID: "S", request: draftRequest(), knownDraftLinkID: nil
            )
        }
        #expect(api.deleted.isEmpty)
        #expect(api.creates.count == 1)
    }

    @Test func realFileNameConflictStillFails() async {
        let api = FakeDraftAPI() // no pending drafts: an ACTIVE file holds the name
        api.createScript = [.failure(duplicate)]
        await #expect(throws: duplicate) {
            _ = try await FileDraftFlow.createDraft(
                api: api, shareID: "S", request: draftRequest(), knownDraftLinkID: nil
            )
        }
        #expect(api.probes == 2)
        #expect(api.deleted.isEmpty)
    }

    @Test func ownStaleDraftsMatchingRules() {
        let pending = [
            pendingDraft("A", clientUID: "CU-1"),
            pendingDraft("B", clientUID: "CU-2"),
            pendingDraft("C", hash: "other", clientUID: "CU-1"),
            pendingDraft("D", clientUID: nil),
            PendingHash(hash: "abc", revisionID: nil, linkID: nil, clientUID: "CU-1"),
        ]
        #expect(FileDraftFlow.ownStaleDrafts(pending: pending, hash: "ABC", clientUID: "CU-1", knownDraftLinkID: nil) == ["A"])
        #expect(FileDraftFlow.ownStaleDrafts(pending: pending, hash: "abc", clientUID: "CU-1", knownDraftLinkID: "D") == ["A", "D"])
        #expect(FileDraftFlow.ownStaleDrafts(pending: pending, hash: "abc", clientUID: nil, knownDraftLinkID: nil).isEmpty)
        #expect(FileDraftFlow.ownStaleDrafts(pending: pending, hash: "abc", clientUID: "", knownDraftLinkID: nil).isEmpty)
    }

    @Test func clientUIDIsEncodedOnlyWhenSet() throws {
        let with = String(data: try JSONEncoder().encode(draftRequest()), encoding: .utf8) ?? ""
        #expect(with.contains(#""ClientUID":"CU-1""#))
        let without = String(data: try JSONEncoder().encode(draftRequest(clientUID: nil)), encoding: .utf8) ?? ""
        #expect(!without.contains("ClientUID"))
    }
}
