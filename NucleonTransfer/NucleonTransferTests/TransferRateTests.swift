// Nucleon Transfer — F8.4-U6 transfer speed/ETA suite (Swift Testing).
// Covers the time-weighted EWMA estimator (warm-up, staleness, resets,
// duplicates), the per-id rate book and the subtitle text fragments with a
// fixed locale and an injected clock. Pure Core, no network.
import Foundation
import Testing

@testable import NucleonTransfer

@Suite("TransferRate")
struct TransferRateTests {
    private let t0 = Date(timeIntervalSince1970: 1_760_000_000)
    private let en = Locale(identifier: "en_US")

    private func at(_ seconds: Double) -> Date { t0.addingTimeInterval(seconds) }

    /// Feeds a steady `rate` bytes/s, one sample per second, `count` samples.
    private func steady(rate: Int64, count: Int) -> TransferRateEstimator {
        var e = TransferRateEstimator()
        for i in 0..<count { e.record(bytes: rate * Int64(i), at: at(Double(i))) }
        return e
    }

    // MARK: - estimator

    @Test func hiddenUntilWarmedUp() {
        var e = TransferRateEstimator()
        e.record(bytes: 0, at: at(0))
        #expect(e.bytesPerSecond(now: at(0)) == nil)
        e.record(bytes: 1_000_000, at: at(1))
        #expect(e.bytesPerSecond(now: at(1)) == nil) // 2 samples
        e.record(bytes: 2_000_000, at: at(2))
        #expect(e.bytesPerSecond(now: at(2)) == 1_000_000)
    }

    @Test func needsMinimumElapsedTime() {
        var e = TransferRateEstimator()
        for i in 0..<5 { e.record(bytes: Int64(i) * 100_000, at: at(Double(i) * 0.2)) }
        // 5 samples but only 0.8 s of history.
        #expect(e.bytesPerSecond(now: at(0.8)) == nil)
    }

    @Test func steadyRateConverges() throws {
        let e = steady(rate: 3_200_000, count: 6)
        let rate = try #require(e.bytesPerSecond(now: at(5)))
        #expect(abs(rate - 3_200_000) < 1)
    }

    @Test func smoothsBurstsTowardNewRate() throws {
        var e = steady(rate: 1_000_000, count: 5) // last sample: 4 MB at t=4
        e.record(bytes: 14_000_000, at: at(5)) // one 10 MB/s burst
        let rate = try #require(e.bytesPerSecond(now: at(5)))
        // Moves toward 10 MB/s but far from jumping there (weight ≈ 0.28).
        #expect(rate > 1_000_000)
        #expect(rate < 5_000_000)
    }

    @Test func staleAfterSilence() {
        let e = steady(rate: 1_000_000, count: 5)
        #expect(e.bytesPerSecond(now: at(4 + TransferRateEstimator.staleAfter)) != nil)
        #expect(e.bytesPerSecond(now: at(4 + TransferRateEstimator.staleAfter + 1)) == nil)
    }

    @Test func bytesGoingBackwardsResets() {
        var e = steady(rate: 1_000_000, count: 5)
        e.record(bytes: 0, at: at(5)) // retry restarted from zero
        #expect(e.sampleCount == 1)
        #expect(e.bytesPerSecond(now: at(5)) == nil)
    }

    @Test func clockGoingBackwardsResets() {
        var e = steady(rate: 1_000_000, count: 5)
        e.record(bytes: 5_000_000, at: at(1))
        #expect(e.sampleCount == 1)
    }

    @Test func duplicateObservationIsIgnored() {
        var e = steady(rate: 1_000_000, count: 4)
        let before = e
        e.record(bytes: 3_000_000, at: at(3.01)) // same snapshot seen twice
        #expect(e == before)
    }

    @Test func zeroRateHidesSpeed() {
        var e = TransferRateEstimator()
        for i in 0..<4 { e.record(bytes: 0, at: at(Double(i))) }
        #expect(e.bytesPerSecond(now: at(3)) == nil)
    }

    // MARK: - book

    @Test func bookTracksUploadsAndPrunesFinished() throws {
        var job = TransferJob(
            fileName: "a.bin", relativePath: "a.bin", localPath: "/tmp/a.bin",
            shareID: "s", parentLinkID: "p", bytesTotal: 10_000_000
        )
        job.state = .uploading
        var book = TransferRateBook()
        for i in 0..<3 {
            job.bytesDone = Int64(i) * 1_000_000
            book.record(uploads: [job], at: at(Double(i)))
        }
        let id = job.id.uuidString
        let rate = try #require(book.bytesPerSecond(id: id, now: at(2)))
        #expect(abs(rate - 1_000_000) < 1)

        job.state = .paused
        book.record(uploads: [job], at: at(3))
        #expect(book.estimators[id] == nil)
    }

    @Test func bookUploadPruneLeavesDownloadsAlone() {
        var book = TransferRateBook()
        book.record(id: "download-1", bytes: 0, at: at(0))
        book.record(uploads: [], at: at(1))
        #expect(book.estimators["download-1"] != nil)
        book.remove(id: "download-1")
        #expect(book.estimators.isEmpty)
    }

    /// Review fix (F8.4): the activity store writes the observed book back
    /// only when it changed — idle and duplicate snapshots must compare
    /// equal so they cause no view invalidation.
    @Test func idleAndDuplicateSnapshotsLeaveTheBookEqual() {
        var job = TransferJob(
            fileName: "a.bin", relativePath: "a.bin", localPath: "/tmp/a.bin",
            shareID: "s", parentLinkID: "p", bytesTotal: 10_000_000
        )
        var book = TransferRateBook()
        book.record(id: "download-1", bytes: 5, at: at(0))
        let idle = book
        // Nothing uploading, nothing tracked: no change.
        book.record(uploads: [], at: at(1))
        book.record(uploads: [job], at: at(1)) // queued, not uploading
        #expect(book == idle)

        job.state = .uploading
        job.bytesDone = 1_000
        book.record(uploads: [job], at: at(2))
        #expect(book != idle) // a real sample changes it
        let sampled = book
        book.record(uploads: [job], at: at(2.01)) // same snapshot seen twice
        #expect(book == sampled)

        job.state = .done
        book.record(uploads: [job], at: at(3))
        #expect(book == idle) // estimator dropped, tracking cleared
        book.record(uploads: [job], at: at(4))
        #expect(book == idle)
    }

    // MARK: - text

    @Test func speedText() {
        #expect(TransferRateText.speed(3_200_000, locale: en) == "3.2 MB/s")
    }

    @Test func etaText() {
        #expect(TransferRateText.eta(seconds: 7, locale: en) == "10 sec left")
        #expect(TransferRateText.eta(seconds: 54, locale: en) == "55 sec left")
        #expect(TransferRateText.eta(seconds: 0.4, locale: en) == "5 sec left")
        #expect(TransferRateText.eta(seconds: 59.5, locale: en) == "1 min left")
        #expect(TransferRateText.eta(seconds: 61, locale: en) == "2 min left")
        #expect(TransferRateText.eta(seconds: 3700, locale: en) == "1 hr, 2 min left")
    }

    @Test func secondsRemainingGuards() {
        #expect(TransferRateText.secondsRemaining(done: 0, total: 0, bytesPerSecond: 1) == nil)
        #expect(TransferRateText.secondsRemaining(done: 0, total: 10, bytesPerSecond: 0) == nil)
        #expect(TransferRateText.secondsRemaining(done: 0, total: 1_000_000_000_000, bytesPerSecond: 1) == nil)
        #expect(TransferRateText.secondsRemaining(done: 40, total: 100, bytesPerSecond: 10) == 6)
    }

    @Test func percentClampsAndRoundsDown() {
        #expect(TransferRateText.percent(0.429) == "42%")
        #expect(TransferRateText.percent(0.999) == "99%")
        #expect(TransferRateText.percent(1.5) == "100%")
        #expect(TransferRateText.percent(-1) == "0%")
    }

    @Test func progressLineComposition() {
        #expect(
            TransferRateText.progressLine(
                fraction: 0.42, done: 42_000_000, total: 100_000_000,
                bytesPerSecond: nil, locale: en
            ) == "42%"
        )
        #expect(
            TransferRateText.progressLine(
                fraction: 0.42, done: 42_000_000, total: 100_000_000,
                bytesPerSecond: 1_000_000, locale: en
            ) == "42% · 1 MB/s · 1 min left"
        )
        // No size known (block-only download) → no ETA.
        #expect(
            TransferRateText.progressLine(
                fraction: 0.42, done: nil, total: nil,
                bytesPerSecond: 1_000_000, locale: en
            ) == "42% · 1 MB/s"
        )
    }
}
