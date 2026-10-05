// Nucleon Transfer — download history model (F6).
// Minimal unification: uploads stay in TransferQueue (upload-specific actor,
// NOT rewritten per F5 scope decision); downloads get a lightweight,
// UI-observable record list so the Transfers tab shows BOTH. Pure Foundation
// (Codable/Sendable) — the @Observable store lives in Features.

import Foundation

enum DownloadState: String, Codable, Sendable, Equatable {
    case downloading
    case done
    case failed
    /// Stopped by the user or by sign-out (F8.2-R5) — not an error.
    case cancelled
}

enum DownloadKind: String, Codable, Sendable, Equatable {
    case file
    case folder
}

/// One user-visible download (file or recursive folder). Secrets-free by
/// construction: only names, counts, destinations and error strings.
struct DownloadRecord: Codable, Sendable, Identifiable, Equatable {
    var id: UUID
    var name: String
    var kind: DownloadKind
    var state: DownloadState
    /// Files downloaded (folders) or 1 (single file, on success).
    var fileCount: Int
    /// Local destination directory name (lastPathComponent, never full path).
    var destinationName: String?
    /// Live 0…1 fraction while `state == .downloading` (S2.3); nil = no
    /// per-block progress yet (folders report file counts instead). The
    /// store clears it on finish/fail so done rows never render stale bars.
    var progress: Double?
    /// Plaintext size of a single-file download (DriveItem.size), for the
    /// speed/ETA line (F8.4-U6). nil for folders and unknown sizes — the
    /// row then shows the percentage only.
    var bytesTotal: Int64?
    var errorMessage: String?
    var startedAt: Date
    var updatedAt: Date

    init(
        id: UUID = UUID(),
        name: String,
        kind: DownloadKind,
        state: DownloadState = .downloading,
        fileCount: Int = 0,
        destinationName: String? = nil,
        progress: Double? = nil,
        bytesTotal: Int64? = nil,
        errorMessage: String? = nil,
        startedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.state = state
        self.fileCount = fileCount
        self.destinationName = destinationName
        self.progress = progress
        self.bytesTotal = bytesTotal
        self.errorMessage = errorMessage
        self.startedAt = startedAt
        self.updatedAt = updatedAt
    }

    /// Bytes written so far, derived from the block fraction × size
    /// (block-granular — the rate estimator smooths the steps). nil
    /// without a size or before the first progress hop.
    var bytesDone: Int64? {
        guard let progress, let bytesTotal, bytesTotal > 0 else { return nil }
        return Int64((progress * Double(bytesTotal)).rounded())
    }

    var stateLabel: String {
        switch state {
        case .downloading: return String(localized: "Downloading")
        case .done: return String(localized: "Done")
        case .failed: return String(localized: "Failed")
        case .cancelled: return String(localized: "Cancelled")
        }
    }

    /// One-line summary for the Transfers tab (no secrets, no full paths).
    var summary: String {
        switch state {
        case .downloading:
            return kind == .folder
                ? String(localized: "Downloading folder…") : String(localized: "Downloading…")
        case .done:
            let done = kind == .folder
                ? String(AttributedString(localized: "Downloaded ^[\(fileCount) file](inflect: true)").characters)
                : String(localized: "Downloaded")
            return done + (destinationName.map { " → \($0)" } ?? "")
        case .failed:
            return errorMessage ?? String(localized: "Download failed")
        case .cancelled:
            return String(localized: "Download cancelled")
        }
    }

    // MARK: - transitions (F8.2-R5)
    // Only an in-flight record changes: done / failed / cancelled are
    // terminal, so a progress hop or a completion that arrives late (after
    // a cancel, or after the record finished) can't put it back in flight.
    // Each returns whether the record changed.

    @discardableResult
    mutating func applyProgress(_ fraction: Double) -> Bool {
        guard state == .downloading else { return false }
        progress = min(max(fraction, 0), 1)
        return true
    }

    @discardableResult
    mutating func finish(fileCount: Int, destinationName: String?, at date: Date = Date()) -> Bool {
        guard state == .downloading else { return false }
        state = .done
        self.fileCount = fileCount
        if let destinationName { self.destinationName = destinationName }
        progress = nil
        errorMessage = nil
        updatedAt = date
        return true
    }

    @discardableResult
    mutating func fail(message: String, at date: Date = Date()) -> Bool {
        guard state == .downloading else { return false }
        state = .failed
        progress = nil
        errorMessage = message
        updatedAt = date
        return true
    }

    @discardableResult
    mutating func cancel(at date: Date = Date()) -> Bool {
        guard state == .downloading else { return false }
        state = .cancelled
        progress = nil
        errorMessage = nil
        updatedAt = date
        return true
    }

    /// True for errors that mean "the task was cancelled", not a failure:
    /// Swift CancellationError and URLSession's cancelled code (bare or
    /// wrapped by APIClient as `.transport`).
    static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let api = error as? ProtonAPIError, case let .transport(underlying) = api {
            return isCancellation(underlying)
        }
        let ns = error as NSError
        return ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled
    }
}
