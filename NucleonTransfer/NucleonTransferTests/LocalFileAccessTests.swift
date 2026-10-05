// Nucleon Transfer — F8.2-R4 sandbox resume (Swift Testing).
// LocalFileAccess with an injected resolver: scope started on the resolved
// bookmark, balanced stop, stale-bookmark refresh, path fallback; plus the
// drop-grant ledger and the queue persisting a refreshed bookmark.
import Foundation
import Testing

@testable import NucleonTransfer

/// Records scope calls; files "exist" per the `existing` set.
final class FakeFS: @unchecked Sendable {
    private let lock = NSLock()
    var existing: Set<String> = []
    var resolved = URL(fileURLWithPath: "/Volumes/Ext/moved/a.txt")
    var stale = false
    var resolveFails = false
    var startResult = true
    private(set) var started: [URL] = []
    private(set) var stopped: [URL] = []
    private(set) var madeBookmarks = 0

    var access: LocalFileAccess {
        LocalFileAccess(
            fileExists: { path in self.lock.withLock { self.existing.contains(path) } },
            resolveBookmark: { _ in
                try self.lock.withLock {
                    if self.resolveFails { throw CocoaError(.fileReadCorruptFile) }
                    return (self.resolved, self.stale)
                }
            },
            makeBookmark: { url in
                self.lock.withLock { self.madeBookmarks += 1 }
                return Data("fresh:\(url.path)".utf8)
            },
            startAccessing: { url in
                self.lock.withLock {
                    self.started.append(url)
                    return self.startResult
                }
            },
            stopAccessing: { url in self.lock.withLock { self.stopped.append(url) } }
        )
    }
}

private func bookmarkedJob() -> TransferJob {
    var job = makeJob()
    job.localPath = "/Users/me/Desktop/a.txt"
    job.localBookmark = Data("old".utf8)
    return job
}

struct LocalFileAccessTests {
    @Test func freshBookmarkStartsScopeAndCloseStopsIt() throws {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        let opened = try fs.access.open(bookmarkedJob())
        #expect(opened.url == fs.resolved)
        #expect(opened.scoped)
        #expect(opened.refreshedBookmark == nil)
        #expect(fs.started == [fs.resolved])
        #expect(fs.stopped.isEmpty) // held for the job…
        fs.access.close(opened)
        #expect(fs.stopped == [fs.resolved]) // …and balanced once
    }

    @Test func staleBookmarkIsRecreatedAndReported() throws {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        fs.stale = true
        let opened = try fs.access.open(bookmarkedJob())
        #expect(opened.refreshedBookmark == Data("fresh:\(fs.resolved.path)".utf8))
        #expect(fs.madeBookmarks == 1)
        fs.access.close(opened)
        #expect(fs.started.count == fs.stopped.count)
    }

    @Test func resolvedButMissingFallsBackToPathAndStopsScope() throws {
        let fs = FakeFS()
        let job = bookmarkedJob()
        fs.existing = [job.localPath] // bookmark target gone, original path still there
        let opened = try fs.access.open(job)
        #expect(opened.url.path == job.localPath)
        #expect(!opened.scoped)
        #expect(fs.stopped == [fs.resolved]) // the speculative scope was released
    }

    @Test func failedStartIsNotStopped() throws {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        fs.startResult = false
        let opened = try fs.access.open(bookmarkedJob())
        fs.access.close(opened)
        #expect(fs.stopped.isEmpty)
    }

    @Test func noBookmarkUsesPath() throws {
        let fs = FakeFS()
        var job = makeJob()
        job.localPath = "/tmp/plain.txt"
        fs.existing = ["/tmp/plain.txt"]
        let opened = try fs.access.open(job)
        #expect(!opened.scoped)
        #expect(fs.started.isEmpty)
    }

    @Test func nothingResolvesIsPermanentMissing() {
        let fs = FakeFS()
        fs.resolveFails = true
        #expect(throws: TransferFailure.permanent(UserFacingError.fileMissing)) {
            _ = try fs.access.open(bookmarkedJob())
        }
        #expect(fs.started.isEmpty)
    }

    // MARK: queue persists the refreshed bookmark

    struct RefreshingUploader: TransferUploader {
        func upload(job: TransferJob, progress: @Sendable (Int64) async -> Void) async throws -> String? {
            "L"
        }

        func upload(
            job: TransferJob,
            progress: @Sendable (Int64) async -> Void,
            events: TransferUploadEvents
        ) async throws -> String? {
            await events.bookmarkRefreshed(Data("new-bookmark".utf8))
            return "L"
        }
    }

    @Test func queuePersistsRefreshedBookmark() async throws {
        let store = CountingStore()
        let q = TransferQueue(store: store, uploader: RefreshingUploader())
        let job = bookmarkedJob()
        await q.enqueue(job)
        await drain(q)
        await q.flush()
        #expect(await q.job(id: job.id)?.localBookmark == Data("new-bookmark".utf8))
        let reloaded = TransferQueueSnapshot.decode(try #require(store.read()))
        #expect(reloaded.jobs.first?.localBookmark == Data("new-bookmark".utf8))
    }

    // MARK: drop-grant ledger

    @Test func grantIsReleasedOnlyWhenAllJobsFinish() {
        var a = makeJob("a"), b = makeJob("b")
        var ledger = UploadGrantLedger<String>()
        ledger.hold("drop", for: [a.id, b.id])
        a.state = .done
        b.state = .paused
        #expect(ledger.releasable(in: [a, b]).isEmpty) // paused job may resume
        b.state = .uploading
        #expect(ledger.releasable(in: [a, b]).isEmpty)
        b.state = .failed
        #expect(ledger.releasable(in: [a, b]) == ["drop"])
        #expect(ledger.isEmpty)
    }

    @Test func removedJobsReleaseTheirGrant() {
        let a = makeJob("a")
        var ledger = UploadGrantLedger<String>()
        ledger.hold("drop", for: [a.id])
        #expect(ledger.releasable(in: []) == ["drop"])
        ledger.hold("x", for: [a.id])
        #expect(ledger.releaseAll() == ["x"])
        #expect(ledger.isEmpty)
    }
}
