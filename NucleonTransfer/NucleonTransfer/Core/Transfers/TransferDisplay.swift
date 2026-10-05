// Nucleon Transfer — unified transfer display model (F7 S3.2).
// One row type for BOTH uploads (TransferQueue jobs) and downloads
// (TransferActivityStore records): pure Foundation mapping so the popover
// view stays thin and every subtitle/section decision is offline-testable.
// Secrets-free by construction: file names, sizes, destination NAMES and
// already-mapped error strings only — no paths, no key material.

import Foundation

/// One row in the transfers popover (spec 6.5). `id` is the underlying
/// job/record UUID string; `direction` tells lookups which store owns it.
/// `isActive` = in-flight section membership (queued / uploading / paused /
/// downloading). `isFailed` drives the red subtitle — cancelled uploads sit
/// in the Failed section but keep a neutral subtitle (user-initiated, not
/// an error); `isCancelled` gives them their own glyph (F8.4-U8: state is
/// never conveyed by color alone).
struct TransferDisplayItem: Identifiable, Sendable, Equatable {
    enum Direction: String, Sendable, Equatable {
        case upload
        case download
    }

    let id: String
    let direction: Direction
    let name: String
    let isFolder: Bool
    let subtitle: String
    let progress: Double?
    let isActive: Bool
    let isFailed: Bool
    var isCancelled = false
    let updatedAt: Date

    /// Finished successfully (Completed section).
    var isDone: Bool { !isActive && !isFailed && !isCancelled }

    /// SF Symbol shown beside the subtitle so the end state reads without
    /// color (F8.4-U8): failed, cancelled or done; nil while in flight.
    var statusSymbol: String? {
        if isFailed { return "exclamationmark.triangle.fill" }
        if isCancelled { return "xmark.circle" }
        if isDone { return "checkmark.circle" }
        return nil
    }

    /// VoiceOver value for the combined row: the subtitle, prefixed with
    /// "Failed" when the subtitle is an error message (the red color and
    /// glyph are invisible to VoiceOver).
    var accessibilityValue: String {
        isFailed ? String(localized: "Failed, \(subtitle)") : subtitle
    }

    /// "42 percent"-style value for the progress bar ("42%").
    var progressText: String? {
        progress.map(TransferRateText.percent)
    }
}

/// Toolbar badge (F8.4-U6; F8.4 review): the in-flight count in the accent
/// tint while anything runs (plus a red marker when something failed);
/// red failed count + glyph once nothing runs; nothing when idle.
enum TransferBadge: Sendable, Equatable {
    case none
    /// Transfers in flight (tinted count). `failed` > 0 adds a red marker:
    /// a failure never hides how much is still running (F8.4 review).
    case active(Int, failed: Int)
    /// Nothing in flight, something failed (red).
    case failed(Int)

    /// VoiceOver / tooltip suffix: "3 active", "3 active, 1 failed",
    /// "2 failed".
    var summary: String? {
        switch self {
        case .none:
            return nil
        case let .active(n, failed):
            let active = String(localized: "\(n) active")
            guard failed > 0 else { return active }
            let failedText = String(localized: "\(failed) failed")
            return String(
                localized: "\(active), \(failedText)",
                comment: "Toolbar badge summary joining both counts: “3 active, 1 failed”"
            )
        case let .failed(n):
            return String(localized: "\(n) failed")
        }
    }
}

/// Popover grouping (spec 6.5): only non-empty sections render, always in
/// this order.
enum TransferDisplaySectionKind: String, Sendable, Equatable, CaseIterable {
    case active = "Active"
    case failed = "Failed"
    case completed = "Completed"

    /// Localizable header text (the raw value stays a stable id).
    var title: String {
        switch self {
        case .active: return String(localized: "Active")
        case .failed: return String(localized: "Failed")
        case .completed: return String(localized: "Completed")
        }
    }
}

struct TransferDisplaySection: Identifiable, Sendable, Equatable {
    let kind: TransferDisplaySectionKind
    let items: [TransferDisplayItem]

    var id: String { kind.rawValue }
    /// Header with the row count: "Failed (3)" (F8.4-U6).
    var title: String {
        let count = items.count
        return String(localized: "\(kind.title) (\(count))", comment: "Transfers section header with row count: “Failed (3)”")
    }
}

enum TransferDisplay {
    // MARK: - item mapping

    /// Upload job → display row. `destinationName` is the breadcrumb
    /// captured at enqueue time ("My Files › Projects"); nil for jobs
    /// restored from disk — the subtitle degrades gracefully.
    /// `bytesPerSecond` is the smoothed rate (TransferRateBook); nil hides
    /// speed and ETA.
    static func item(
        for job: TransferJob, destinationName: String?, bytesPerSecond: Double? = nil
    ) -> TransferDisplayItem {
        TransferDisplayItem(
            id: job.id.uuidString,
            direction: .upload,
            name: job.fileName,
            isFolder: false, // folder uploads land as one job per file
            subtitle: uploadSubtitle(job, destination: destinationName, rate: bytesPerSecond),
            progress: uploadProgress(job),
            isActive: section(of: job) == .active,
            isFailed: job.state == .failed,
            isCancelled: job.state == .cancelled,
            updatedAt: job.updatedAt
        )
    }

    /// Download record → display row. Folder downloads get " (N files)"
    /// appended to the NAME (spec 6.5 wireframe); the subtitle stays
    /// "Downloaded to <destination>".
    static func item(for record: DownloadRecord, bytesPerSecond: Double? = nil) -> TransferDisplayItem {
        TransferDisplayItem(
            id: record.id.uuidString,
            direction: .download,
            name: downloadName(record),
            isFolder: record.kind == .folder,
            subtitle: downloadSubtitle(record, rate: bytesPerSecond),
            progress: record.state == .downloading ? record.progress : nil,
            isActive: record.state == .downloading,
            isFailed: record.state == .failed,
            isCancelled: record.state == .cancelled,
            updatedAt: record.updatedAt
        )
    }

    // MARK: - sections

    /// Uploads + downloads merged into Active / Failed / Completed, each
    /// sorted `updatedAt` descending (spec 6.5). `destinationName` resolves
    /// a job's breadcrumb — pass `UploadCoordinator.destinationNames` via a
    /// closure so this file never touches Features types. `bytesPerSecond`
    /// resolves a smoothed rate by item id (TransferRateBook) the same way.
    static func sections(
        uploads: [TransferJob],
        downloads: [DownloadRecord],
        destinationName: (UUID) -> String? = { _ in nil },
        bytesPerSecond: (String) -> Double? = { _ in nil }
    ) -> [TransferDisplaySection] {
        var grouped: [TransferDisplaySectionKind: [TransferDisplayItem]] = [:]
        for job in uploads {
            let rate = job.state == .uploading ? bytesPerSecond(job.id.uuidString) : nil
            grouped[section(of: job), default: []]
                .append(item(for: job, destinationName: destinationName(job.id), bytesPerSecond: rate))
        }
        for record in downloads {
            let rate = record.state == .downloading ? bytesPerSecond(record.id.uuidString) : nil
            grouped[section(of: record), default: []]
                .append(item(for: record, bytesPerSecond: rate))
        }
        return TransferDisplaySectionKind.allCases.compactMap { kind in
            guard var items = grouped[kind], !items.isEmpty else { return nil }
            items.sort { $0.updatedAt > $1.updatedAt }
            return TransferDisplaySection(kind: kind, items: items)
        }
    }

    static func section(of job: TransferJob) -> TransferDisplaySectionKind {
        switch job.state {
        case .queued, .uploading, .paused: return .active
        case .failed, .cancelled: return .failed
        case .done: return .completed
        }
    }

    static func section(of record: DownloadRecord) -> TransferDisplaySectionKind {
        switch record.state {
        case .downloading: return .active
        case .failed, .cancelled: return .failed
        case .done: return .completed
        }
    }

    /// Active-transfer count for the toolbar badge: queued, uploading,
    /// paused and in-flight downloads.
    static func activeCount(uploads: [TransferJob], downloads: [DownloadRecord]) -> Int {
        uploads.filter { section(of: $0) == .active }.count
            + downloads.filter { $0.state == .downloading }.count
    }

    /// Failed (not cancelled) uploads + downloads.
    static func failedCount(uploads: [TransferJob], downloads: [DownloadRecord]) -> Int {
        uploads.filter { $0.state == .failed }.count
            + downloads.filter { $0.state == .failed }.count
    }

    /// Toolbar badge state: the active count while anything is in flight
    /// (carrying the failed count for its marker), red only once nothing
    /// runs and something actually failed.
    static func badge(uploads: [TransferJob], downloads: [DownloadRecord]) -> TransferBadge {
        let failed = failedCount(uploads: uploads, downloads: downloads)
        let active = activeCount(uploads: uploads, downloads: downloads)
        if active > 0 { return .active(active, failed: failed) }
        return failed > 0 ? .failed(failed) : .none
    }

    // MARK: - subtitles

    private static func uploadSubtitle(
        _ job: TransferJob, destination: String?, rate: Double?
    ) -> String {
        switch job.state {
        case .queued:
            return String(localized: "Waiting…", comment: "Queued upload subtitle")
        case .uploading:
            // F8.4-U6: "42% · 3.2 MB/s · 1 min left" once the rate has
            // warmed up; until then percent + byte counts + destination.
            if let rate {
                return TransferRateText.progressLine(
                    fraction: job.progress, done: job.bytesDone,
                    total: job.bytesTotal, bytesPerSecond: rate
                )
            }
            var text = TransferRateText.percent(job.progress)
                + " · " + ofBytes(job.bytesDone, job.bytesTotal)
            if let destination, !destination.isEmpty {
                text += " · " + String(localized: "to \(destination)", comment: "Upload subtitle fragment: destination folder")
            }
            return text
        case .paused:
            guard job.bytesTotal > 0 else { return String(localized: "Paused") }
            return String(localized: "Paused") + " · " + ofBytes(job.bytesDone, job.bytesTotal)
        case .done:
            if let destination, !destination.isEmpty {
                return String(localized: "Uploaded to \(destination)")
            }
            return String(localized: "Uploaded")
        case .failed:
            return UserFacingError.message(forJob: job)
        case .cancelled:
            return String(localized: "Cancelled")
        }
    }

    /// A progress bar shows only while bytes are visibly moving: uploading
    /// always, paused only with partial progress (mirrors the legacy row).
    private static func uploadProgress(_ job: TransferJob) -> Double? {
        switch job.state {
        case .uploading:
            return job.progress
        case .paused:
            return job.bytesDone > 0 ? job.progress : nil
        case .queued, .done, .failed, .cancelled:
            return nil
        }
    }

    private static func downloadName(_ record: DownloadRecord) -> String {
        guard record.kind == .folder, record.fileCount > 0 else { return record.name }
        // Plural via inflection (catalog plural variants in the app). The
        // name stays out of the attributed string — Markdown in a file
        // name must never be parsed.
        let files = String(AttributedString(
            localized: "^[\(record.fileCount) file](inflect: true)",
            comment: "File count, e.g. in a folder download row"
        ).characters)
        return String(localized: "\(record.name) (\(files))", comment: "Folder download row: name and file count")
    }

    private static func downloadSubtitle(_ record: DownloadRecord, rate: Double?) -> String {
        switch record.state {
        case .downloading:
            if let progress = record.progress {
                if let rate {
                    return TransferRateText.progressLine(
                        fraction: progress, done: record.bytesDone,
                        total: record.bytesTotal, bytesPerSecond: rate
                    )
                }
                let percent = TransferRateText.percent(progress)
                return String(localized: "Downloading… \(percent)")
            }
            return record.kind == .folder
                ? String(localized: "Downloading folder…") : String(localized: "Downloading…")
        case .done:
            if let destination = record.destinationName, !destination.isEmpty {
                return String(localized: "Downloaded to \(destination)")
            }
            return String(localized: "Downloaded")
        case .failed:
            // Store already maps errors via UserFacingError.message(for:);
            // the message(forMessage:) pass upgrades any raw string too.
            return UserFacingError.message(forMessage: record.errorMessage ?? String(localized: "Download failed"))
        case .cancelled:
            return String(localized: "Cancelled")
        }
    }

    /// "1.2 MB of 4 MB".
    private static func ofBytes(_ done: Int64, _ total: Int64) -> String {
        let doneText = bytes(done)
        let totalText = bytes(total)
        return String(localized: "\(doneText) of \(totalText)", comment: "Transfer progress: bytes done of total")
    }

    private static func bytes(_ n: Int64) -> String {
        n.formatted(ByteCountFormatStyle(style: .file))
    }
}
