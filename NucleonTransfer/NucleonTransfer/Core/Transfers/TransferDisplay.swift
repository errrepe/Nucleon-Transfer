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

    /// SF Symbol shown beside the subtitle so failure/cancellation reads
    /// without color (F8.4-U8); nil for every other state.
    var statusSymbol: String? {
        if isFailed { return "exclamationmark.triangle.fill" }
        if isCancelled { return "xmark.circle" }
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

/// Toolbar badge (F8.4-U6): failures win (red, failed count + glyph);
/// otherwise the in-flight count in the accent tint; nothing when idle.
enum TransferBadge: Sendable, Equatable {
    case none
    case active(Int)
    case failed(Int)

    /// VoiceOver / tooltip suffix: "3 active", "2 failed".
    var summary: String? {
        switch self {
        case .none: return nil
        case let .active(n): return String(localized: "\(n) active")
        case let .failed(n): return String(localized: "\(n) failed")
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
    var title: String { "\(kind.title) (\(items.count))" }
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

    /// Toolbar badge state: red only when something actually failed.
    static func badge(uploads: [TransferJob], downloads: [DownloadRecord]) -> TransferBadge {
        let failed = failedCount(uploads: uploads, downloads: downloads)
        if failed > 0 { return .failed(failed) }
        let active = activeCount(uploads: uploads, downloads: downloads)
        return active > 0 ? .active(active) : .none
    }

    // MARK: - subtitles

    private static func uploadSubtitle(
        _ job: TransferJob, destination: String?, rate: Double?
    ) -> String {
        switch job.state {
        case .queued:
            return "Waiting…"
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
                + " · \(bytes(job.bytesDone)) of \(bytes(job.bytesTotal))"
            if let destination, !destination.isEmpty {
                text += " · to \(destination)"
            }
            return text
        case .paused:
            guard job.bytesTotal > 0 else { return "Paused" }
            return "Paused · \(bytes(job.bytesDone)) of \(bytes(job.bytesTotal))"
        case .done:
            if let destination, !destination.isEmpty {
                return "Uploaded to \(destination)"
            }
            return "Uploaded"
        case .failed:
            return UserFacingError.message(forMessage: job.errorMessage ?? "Upload failed")
        case .cancelled:
            return "Cancelled"
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
        let noun = record.fileCount == 1 ? "file" : "files"
        return "\(record.name) (\(record.fileCount) \(noun))"
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
                return "Downloading… \(TransferRateText.percent(progress))"
            }
            return record.kind == .folder ? "Downloading folder…" : "Downloading…"
        case .done:
            if let destination = record.destinationName, !destination.isEmpty {
                return "Downloaded to \(destination)"
            }
            return "Downloaded"
        case .failed:
            // Store already maps errors via UserFacingError.message(for:);
            // the message(forMessage:) pass upgrades any raw string too.
            return UserFacingError.message(forMessage: record.errorMessage ?? "Download failed")
        case .cancelled:
            return "Cancelled"
        }
    }

    private static func bytes(_ n: Int64) -> String {
        n.formatted(ByteCountFormatStyle(style: .file))
    }
}
