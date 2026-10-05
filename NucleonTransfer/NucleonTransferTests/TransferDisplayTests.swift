// Nucleon Transfer — S3.2 transfers-popover mapping suite (Swift Testing).
// Covers TransferJob/DownloadRecord → TransferDisplayItem subtitles,
// section grouping, ordering and the badge count. Pure Core, no network.
import Foundation
import Testing

@testable import NucleonTransfer

@Suite("TransferDisplay")
struct TransferDisplayTests {
    /// Job factory: `init` always starts `.queued`, so callers mutate the
    /// returned value into the state under test.
    private func job(
        state: TransferJobState,
        fileName: String = "video.mov",
        bytesDone: Int64 = 0,
        bytesTotal: Int64 = 80_000_000,
        errorMessage: String? = nil,
        updatedAt: Date = Date(timeIntervalSince1970: 1_760_000_000)
    ) -> TransferJob {
        var j = TransferJob(
            fileName: fileName,
            relativePath: fileName,
            localPath: "/tmp/\(fileName)",
            shareID: "share-1",
            parentLinkID: "link-parent",
            bytesTotal: bytesTotal
        )
        j.state = state
        j.bytesDone = bytesDone
        j.errorMessage = errorMessage
        j.updatedAt = updatedAt
        return j
    }

    private func record(
        state: DownloadState,
        name: String = "Projects",
        kind: DownloadKind = .file,
        fileCount: Int = 0,
        destinationName: String? = "Downloads",
        progress: Double? = nil,
        errorMessage: String? = nil,
        updatedAt: Date = Date(timeIntervalSince1970: 1_760_000_000)
    ) -> DownloadRecord {
        DownloadRecord(
            name: name, kind: kind, state: state, fileCount: fileCount,
            destinationName: destinationName, progress: progress,
            errorMessage: errorMessage, updatedAt: updatedAt
        )
    }

    // MARK: - upload subtitles

    @Test func uploadingSubtitleShowsBytesAndDestination() {
        let j = job(state: .uploading, bytesDone: 40_000_000)
        let item = TransferDisplay.item(for: j, destinationName: "My Files › Projects")
        #expect(item.direction == .upload)
        #expect(item.subtitle.contains("of"))
        #expect(item.subtitle.hasSuffix("· to My Files › Projects"))
        #expect(item.isActive)
        #expect(!item.isFailed)
        #expect(item.progress == 0.5)
    }

    @Test func uploadingSubtitleWithoutDestinationOmitsSuffix() {
        let j = job(state: .uploading, bytesDone: 40_000_000)
        let item = TransferDisplay.item(for: j, destinationName: nil)
        #expect(!item.subtitle.contains("· to"))
    }

    @Test func queuedUploadWaits() {
        let item = TransferDisplay.item(for: job(state: .queued), destinationName: "My Files")
        #expect(item.subtitle == "Waiting…")
        #expect(item.isActive)
        #expect(item.progress == nil) // no bar for a queued row
    }

    @Test func pausedUploadShowsBytes() {
        let item = TransferDisplay.item(
            for: job(state: .paused, bytesDone: 40_000_000),
            destinationName: nil
        )
        #expect(item.subtitle.hasPrefix("Paused ·"))
        #expect(item.progress == 0.5) // partial progress bar survives the pause
        #expect(item.isActive)
    }

    @Test func pausedUploadAtZeroHidesBar() {
        let item = TransferDisplay.item(for: job(state: .paused), destinationName: nil)
        #expect(item.progress == nil)
    }

    @Test func doneUploadNamesDestination() {
        let item = TransferDisplay.item(
            for: job(state: .done, bytesDone: 80_000_000),
            destinationName: "My Files › Projects"
        )
        #expect(item.subtitle == "Uploaded to My Files › Projects")
        #expect(!item.isActive && !item.isFailed)
        #expect(item.progress == nil)
    }

    @Test func doneUploadWithoutDestination() {
        let item = TransferDisplay.item(for: job(state: .done), destinationName: nil)
        #expect(item.subtitle == "Uploaded")
    }

    @Test func failedUploadMapsMessage() {
        let item = TransferDisplay.item(
            for: job(state: .failed, errorMessage: "api 500: oops"),
            destinationName: nil
        )
        #expect(item.isFailed)
        #expect(!item.isActive)
        // Raw API strings are upgraded to actionable guidance.
        #expect(item.subtitle.contains("servers are having trouble"))
        #expect(item.subtitle.hasSuffix("(Error 500)"))
    }

    @Test func cancelledUploadReadsCancelledNotRed() {
        let item = TransferDisplay.item(for: job(state: .cancelled), destinationName: nil)
        #expect(item.subtitle == "Cancelled")
        #expect(!item.isFailed) // cancelled is user-initiated: neutral, not red
        #expect(TransferDisplay.section(of: job(state: .cancelled)) == .failed)
    }

    // MARK: - download rows

    @Test func downloadingSubtitleShowsPercent() {
        let item = TransferDisplay.item(for: record(state: .downloading, progress: 0.45))
        #expect(item.subtitle == "Downloading… 45%")
        #expect(item.isActive)
        #expect(item.progress == 0.45)
    }

    @Test func downloadingFolderWithoutProgress() {
        let item = TransferDisplay.item(
            for: record(state: .downloading, kind: .folder, progress: nil)
        )
        #expect(item.subtitle == "Downloading folder…")
        #expect(item.progress == nil)
    }

    @Test func doneFolderDownloadGetsFileCountInName() {
        let item = TransferDisplay.item(
            for: record(state: .done, kind: .folder, fileCount: 14)
        )
        #expect(item.name == "Projects (14 files)")
        #expect(item.subtitle == "Downloaded to Downloads")
        #expect(item.isFolder)
        #expect(!item.isActive && !item.isFailed)
    }

    @Test func doneFileDownloadKeepsName() {
        let item = TransferDisplay.item(for: record(state: .done, name: "big.iso"))
        #expect(item.name == "big.iso")
        #expect(!item.isFolder)
    }

    @Test func failedDownloadSurfacesError() {
        let item = TransferDisplay.item(
            for: record(state: .failed, errorMessage: "Network connection lost.")
        )
        #expect(item.subtitle == "Network connection lost.")
        #expect(item.isFailed && !item.isActive)
    }

    // MARK: - sections + ordering

    @Test func sectionsGroupAndSortByUpdatedAtDesc() {
        let older = Date(timeIntervalSince1970: 1_760_000_000)
        let newer = Date(timeIntervalSince1970: 1_760_000_100)
        let uploads = [
            job(state: .uploading, fileName: "old-up.mov", updatedAt: older),
            job(state: .queued, fileName: "new-up.mov", updatedAt: newer),
            job(state: .done, fileName: "done.mov", updatedAt: newer),
        ]
        let downloads = [
            record(state: .downloading, name: "mid-dl.bin", updatedAt: older
                .addingTimeInterval(50)),
            record(state: .failed, name: "bad.iso", errorMessage: "x",
                   updatedAt: newer),
        ]
        let sections = TransferDisplay.sections(uploads: uploads, downloads: downloads)

        #expect(sections.map(\.kind) == [.active, .failed, .completed])
        let active = sections[0].items
        #expect(active.map(\.name) == ["new-up.mov", "mid-dl.bin", "old-up.mov"])
        #expect(sections[1].items.map(\.name) == ["bad.iso"])
        #expect(sections[2].items.map(\.name) == ["done.mov"])
    }

    @Test func emptyKindsDropTheirSection() {
        let sections = TransferDisplay.sections(
            uploads: [job(state: .done)],
            downloads: []
        )
        #expect(sections.map(\.kind) == [.completed])
    }

    @Test func destinationLookupFeedsSubtitles() {
        let j = job(state: .uploading, bytesDone: 1)
        let sections = TransferDisplay.sections(
            uploads: [j], downloads: [],
            destinationName: { id in id == j.id ? "My Files" : nil }
        )
        #expect(sections.first?.items.first?.subtitle.contains("to My Files") == true)
    }

    @Test func activeCountSpansUploadsAndDownloads() {
        let uploads = [
            job(state: .uploading), job(state: .paused),
            job(state: .done), job(state: .failed),
        ]
        let downloads = [
            record(state: .downloading), record(state: .done),
        ]
        #expect(TransferDisplay.activeCount(uploads: uploads, downloads: downloads) == 3)
    }

    // MARK: - F8.4-U6 progress line, badge, section counts

    @Test func uploadingWithoutRateLeadsWithPercent() {
        let j = job(state: .uploading, bytesDone: 33_600_000) // 42%
        let item = TransferDisplay.item(for: j, destinationName: nil)
        #expect(item.subtitle.hasPrefix("42% · "))
        #expect(!item.subtitle.contains("/s"))
    }

    @Test func uploadingWithRateShowsSpeedAndETA() {
        let j = job(state: .uploading, bytesDone: 40_000_000) // 50% of 80 MB
        let item = TransferDisplay.item(
            for: j, destinationName: "My Files", bytesPerSecond: 2_000_000
        )
        // 40 MB left at 2 MB/s = 20 s.
        #expect(item.subtitle.hasPrefix("50% · "))
        #expect(item.subtitle.contains("/s · "))
        #expect(item.subtitle.hasSuffix(" left"))
    }

    @Test func downloadWithRateAndSizeShowsETA() {
        var r = record(state: .downloading, progress: 0.5)
        r.bytesTotal = 10_000_000
        #expect(r.bytesDone == 5_000_000)
        let item = TransferDisplay.item(for: r, bytesPerSecond: 1_000_000)
        #expect(item.subtitle.hasPrefix("50% · "))
        #expect(item.subtitle.hasSuffix(" left"))
    }

    @Test func downloadWithRateButNoSizeOmitsETA() {
        let r = record(state: .downloading, progress: 0.5)
        #expect(r.bytesDone == nil)
        let item = TransferDisplay.item(for: r, bytesPerSecond: 1_000_000)
        #expect(item.subtitle.hasPrefix("50% · "))
        #expect(!item.subtitle.contains("left"))
    }

    @Test func sectionsPassRatesOnlyToInFlightRows() {
        let up = job(state: .uploading, bytesDone: 40_000_000)
        let done = job(state: .done, bytesDone: 80_000_000)
        let sections = TransferDisplay.sections(
            uploads: [up, done], downloads: [],
            bytesPerSecond: { _ in 1_000_000 }
        )
        #expect(sections[0].items[0].subtitle.contains("/s"))
        #expect(sections[1].items[0].subtitle == "Uploaded")
    }

    @Test func sectionTitlesCarryCounts() {
        let sections = TransferDisplay.sections(
            uploads: [job(state: .failed), job(state: .cancelled), job(state: .done)],
            downloads: [record(state: .failed, errorMessage: "x")]
        )
        #expect(sections.map(\.title) == ["Failed (3)", "Completed (1)"])
        #expect(sections.map(\.id) == ["Failed", "Completed"])
    }

    @Test func badgeIsRedOnlyWhenSomethingFailed() {
        #expect(TransferDisplay.badge(uploads: [], downloads: []) == .none)
        #expect(
            TransferDisplay.badge(
                uploads: [job(state: .uploading), job(state: .cancelled)],
                downloads: [record(state: .downloading), record(state: .cancelled)]
            ) == .active(2, failed: 0)
        )
        #expect(
            TransferDisplay.badge(
                uploads: [job(state: .failed)],
                downloads: [record(state: .failed, errorMessage: "x"), record(state: .done)]
            ) == .failed(2)
        )
        #expect(TransferBadge.active(2, failed: 0).summary == "2 active")
        #expect(TransferBadge.failed(1).summary == "1 failed")
        #expect(TransferBadge.none.summary == nil)
    }

    /// Review fix (F8.4): a failure no longer hides what is still running.
    @Test func badgeKeepsTheActiveCountWhenSomethingFailed() {
        let badge = TransferDisplay.badge(
            uploads: [job(state: .uploading), job(state: .queued), job(state: .failed)],
            downloads: [record(state: .downloading), record(state: .failed, errorMessage: "x")]
        )
        #expect(badge == .active(3, failed: 2))
        #expect(TransferBadge.active(3, failed: 1).summary == "3 active, 1 failed")
    }

    // MARK: - F8.4-U8 status glyphs + VoiceOver value

    @Test func statusGlyphsDoNotRelyOnColor() {
        let failed = TransferDisplay.item(for: job(state: .failed), destinationName: nil)
        let cancelled = TransferDisplay.item(for: record(state: .cancelled))
        let done = TransferDisplay.item(for: record(state: .done))
        let active = TransferDisplay.item(for: record(state: .downloading))
        #expect(failed.statusSymbol == "exclamationmark.triangle.fill")
        #expect(cancelled.statusSymbol == "xmark.circle")
        #expect(cancelled.isCancelled && !cancelled.isFailed)
        #expect(done.statusSymbol == "checkmark.circle")
        #expect(done.isDone && !failed.isDone && !cancelled.isDone)
        #expect(active.statusSymbol == nil && !active.isDone)
    }

    @Test func accessibilityValuePrefixesFailures() {
        let failed = TransferDisplay.item(
            for: record(state: .failed, errorMessage: "Network connection lost.")
        )
        #expect(failed.accessibilityValue == "Failed, Network connection lost.")
        let active = TransferDisplay.item(for: record(state: .downloading, progress: 0.45))
        #expect(active.accessibilityValue == active.subtitle)
        #expect(active.progressText == "45%")
        #expect(TransferDisplay.item(for: record(state: .done)).progressText == nil)
    }
}
