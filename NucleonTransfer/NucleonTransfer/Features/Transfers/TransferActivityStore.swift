// Nucleon Transfer — shared transfers activity (F6; S2.3 progress +
// remote-changed signal).
// Minimal upload+download unification WITHOUT rewriting TransferQueue:
// uploads stay in the TransferQueue actor; downloads (F5 dedicated
// downloader, S2.3 DownloadCoordinator) report lightweight records here so
// ONE Transfers surface shows both. Post-operation consistency (S2.3):
// upload/folder/trash ops publish the touched parent linkIDs via
// `remoteChanged` — browsers observe `remoteChangedToken` and mark those
// folders stale (BrowserModel.markStale) instead of a blind global refresh.
// Speed/ETA (F8.4-U6): a TransferRateBook (Core) keeps one smoothed rate
// per in-flight transfer — downloads feed it from `downloadProgress`,
// uploads from the queue snapshots (`recordUploadProgress`).

import Foundation

@MainActor
@Observable
final class TransferActivityStore {
    var downloads: [DownloadRecord] = []
    /// Record ID → local file/folder URL for a future "Reveal in Finder"
    /// action. In-memory only (never Codable): DownloadRecord keeps the
    /// destination NAME only — full paths stay out of the record and out
    /// of any persisted state, for privacy.
    private(set) var revealURLs: [UUID: URL] = [:]
    /// Parent linkIDs whose remote contents changed since the last
    /// published token. Accumulates (union) so a burst of ops between two
    /// view passes never drops a parent; `markStale` only flags cache
    /// entries, so a lingering parent degrades to a lazy refresh on visit.
    private(set) var remoteChangedParents: Set<String> = []
    /// Incremented on every `remoteChanged` — views key `.task(id:)` on it.
    private(set) var remoteChangedToken = 0
    /// Set by UploadCoordinator on intake (S3.1); S3.2's toolbar button
    /// binds the transfers popover to this flag.
    var presentTransfers = false
    /// Bumped whenever an upload or download batch starts, whether or not
    /// the popover opens for it — the toolbar button bounces on it while
    /// the popover is closed. Only ever goes up.
    private(set) var transfersStarted = 0
    /// Smoothed byte rates by transfer id (F8.4-U6). Observed, so the
    /// popover re-renders as samples land.
    private(set) var rates = TransferRateBook()
    /// Sample clock — injectable so previews/tests can pin time.
    @ObservationIgnored private let now: @MainActor () -> Date

    init(now: @escaping @MainActor () -> Date = { Date() }) {
        self.now = now
    }

    /// `bytesTotal`: plaintext size of a single file (speed/ETA line);
    /// nil for folders.
    func downloadStarted(
        name: String, kind: DownloadKind, destination: URL?, bytesTotal: Int64? = nil
    ) -> UUID {
        let rec = DownloadRecord(
            name: name, kind: kind, state: .downloading,
            destinationName: destination?.lastPathComponent,
            bytesTotal: bytesTotal
        )
        downloads.insert(rec, at: 0)
        trim()
        return rec.id
    }

    /// Per-block progress while downloading (0…1, clamped). Unknown ids
    /// are ignored so a cleared record can't resurrect, and so is progress
    /// for a finished/cancelled record — a late hop can't put a bar back on
    /// a done row (F8.2-R5, DownloadRecord.applyProgress).
    func downloadProgress(id: UUID, fraction: Double) {
        guard let i = downloads.firstIndex(where: { $0.id == id }),
              downloads[i].applyProgress(fraction)
        else { return }
        if let bytes = downloads[i].bytesDone {
            let date = now()
            updateRates { $0.record(id: id.uuidString, bytes: bytes, at: date) }
        }
    }

    /// Upload samples for the rate book: every queue snapshot
    /// (UploadCoordinator's listener is the single caller, F8.4-U7b).
    /// Duplicate observations of one snapshot are dropped by the estimator,
    /// and a snapshot with nothing uploading (and nothing tracked) leaves
    /// the book untouched — no observation churn on idle snapshots.
    func recordUploadProgress(_ jobs: [TransferJob]) {
        let date = now()
        updateRates { $0.record(uploads: jobs, at: date) }
    }

    /// Applies `change` to a copy of the book and writes it back only when
    /// it actually changed: every assignment to the observed `rates`
    /// invalidates the views reading it, even with an equal value.
    private func updateRates(_ change: (inout TransferRateBook) -> Void) {
        var book = rates
        change(&book)
        if book != rates { rates = book }
    }

    /// Smoothed bytes/second for an in-flight transfer, nil while warming
    /// up or stalled. `at` is the render time (the popover ticks it).
    func bytesPerSecond(id: String, at date: Date) -> Double? {
        rates.bytesPerSecond(id: id, now: date)
    }

    /// Terminal transitions only apply to in-flight records (DownloadRecord
    /// transitions): a cancelled download never flips to done or failed.
    func downloadFinished(id: UUID, fileCount: Int, destination: URL?, reveal: URL? = nil) {
        guard let i = downloads.firstIndex(where: { $0.id == id }),
              downloads[i].finish(
                  fileCount: fileCount, destinationName: destination?.lastPathComponent
              )
        else { return }
        updateRates { $0.remove(id: id.uuidString) }
        if let reveal {
            revealURLs[id] = reveal
        } else if let destination {
            revealURLs[id] = destination
        }
    }

    func downloadFailed(id: UUID, error: Error) {
        guard let i = downloads.firstIndex(where: { $0.id == id }) else { return }
        downloads[i].fail(message: UserFacingError.message(for: error))
        updateRates { $0.remove(id: id.uuidString) }
    }

    /// User cancel or sign-out (F8.2-R5): neutral "Cancelled", not a failure.
    func downloadCancelled(id: UUID) {
        guard let i = downloads.firstIndex(where: { $0.id == id }) else { return }
        downloads[i].cancel()
        updateRates { $0.remove(id: id.uuidString) }
    }

    func clearFinished() {
        let keep = downloads.filter { $0.state == .downloading }
        let removed = Set(downloads.map(\.id)).subtracting(keep.map(\.id))
        downloads = keep
        for id in removed { revealURLs.removeValue(forKey: id) }
    }

    /// Removes one record — the row-level dismiss in the S3.2 popover
    /// (failed rows, or a completed row the user clears individually).
    func removeDownload(id: UUID) {
        downloads.removeAll { $0.id == id }
        revealURLs.removeValue(forKey: id)
        updateRates { $0.remove(id: id.uuidString) }
    }

    /// Post-operation consistency (S2.3): publish the parent linkIDs a
    /// remote mutation touched (folder create, trash, upload enqueue/done).
    /// Browsers keyed on `remoteChangedToken` call `markStale` — only the
    /// affected folders refetch, and only on demand.
    /// An upload/download batch started (UploadCoordinator intake,
    /// DownloadCoordinator batch) — see `transfersStarted`.
    func noteTransferStarted() {
        transfersStarted += 1
    }

    func remoteChanged(parentLinkIDs: [String]) {
        remoteChangedParents.formUnion(parentLinkIDs)
        remoteChangedToken += 1
    }

    private func trim() {
        if downloads.count > 50 {
            let dropped = downloads.suffix(from: 50).map(\.id)
            downloads = Array(downloads.prefix(50))
            for id in dropped {
                revealURLs.removeValue(forKey: id)
                updateRates { $0.remove(id: id.uuidString) }
            }
        }
    }
}
