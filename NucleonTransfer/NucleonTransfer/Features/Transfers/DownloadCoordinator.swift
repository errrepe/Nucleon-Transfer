// Nucleon Transfer — browser download orchestration (F7 S2.3; F8.2-R5
// cancellation).
// Extracted from the pre-F7 browser view-model, same behavior: the user picks
// ONE destination folder for the whole batch, then items download
// SEQUENTIALLY (a file via downloadSingleFile with per-block progress, a
// folder via downloadTree preserving structure). Each item reports a
// DownloadRecord to the shared activity store; failures land on the
// record, never block the remaining items. Downloads do not mutate the
// remote tree, so the browser is NOT invalidated afterwards.
// Cancellation (F8.2-R5): each item runs in its own Task keyed by its
// record ID — `cancel(id)` stops one (the batch moves on), `cancelAll()`
// stops every item and the rest of every batch (sign-out calls it before
// the keys are dropped, so no download outlives the session). A cancelled
// item lands as `.cancelled`, never `.failed`; the adapter removes its
// temp file.
// Security scope: the panel URL arrives already started; we still call
// startAccessing (harmless no-op) and ALWAYS balance it with
// stopAccessing when the batch ends.
import Foundation

@MainActor
final class DownloadCoordinator {
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver
    private let activity: TransferActivityStore
    /// LinkIDs with a download in flight — a double activation never
    /// duplicates a transfer (the legacy `downloading` set did the same).
    private var inFlight: Set<String> = []
    /// Guards against two destination panels stacking when the user
    /// triggers Download twice in quick succession.
    private var choosingDestination = false
    /// Record ID → the Task downloading that item (F8.2-R5).
    private var tasks: [UUID: Task<Void, Never>] = [:]
    /// Bumped by `cancelAll`: a batch started under an older epoch stops
    /// before its next item (and after the destination panel returns).
    private var epoch = 0

    init(drive: DriveClient, addressKeys: [KeyringCache.UnlockedKey], resolver: NodeKeyResolver, activity: TransferActivityStore) {
        self.drive = drive
        self.addressKeys = addressKeys
        self.resolver = resolver
        self.activity = activity
    }

    /// Picks one destination folder, then downloads `items` one by one.
    /// Cancellation (nil panel result) silently no-ops — the user dismissed.
    func download(_ items: [DriveItem]) async {
        guard !items.isEmpty, !choosingDestination else { return }
        let batchEpoch = epoch
        choosingDestination = true
        defer { choosingDestination = false }
        guard let destination = await Panels.chooseDownloadFolder(),
              batchEpoch == epoch
        else { return }
        let scoped = destination.startAccessingSecurityScopedResource()
        defer { if scoped { destination.stopAccessingSecurityScopedResource() } }
        let adapter = DriveDownloadAdapter(
            drive: drive, addressKeys: addressKeys, resolver: resolver
        )
        for item in items {
            guard batchEpoch == epoch else { return }
            await download(item, with: adapter, to: destination)
        }
    }

    /// Cancels one in-flight download (transfers row / context menu).
    /// Unknown or finished IDs are a no-op.
    func cancel(_ id: UUID) {
        tasks[id]?.cancel()
    }

    /// Cancels every in-flight download and the remainder of every batch,
    /// then waits for them to unwind (sign-out: nothing keeps the adapter
    /// or its address-key copies alive past this call).
    func cancelAll() async {
        epoch += 1
        let running = Array(tasks.values)
        for task in running { task.cancel() }
        for task in running { await task.value }
    }

    /// One item, errors captured on its record so the batch continues.
    private func download(
        _ item: DriveItem, with adapter: DriveDownloadAdapter, to destination: URL
    ) async {
        guard !inFlight.contains(item.id) else { return }
        inFlight.insert(item.id)
        defer { inFlight.remove(item.id) }
        let recordID = activity.downloadStarted(
            name: item.name,
            kind: item.isFolder ? .folder : .file,
            destination: destination
        )
        let task = Task { [activity] in
            await Self.run(
                item, recordID: recordID, adapter: adapter,
                destination: destination, activity: activity
            )
        }
        tasks[recordID] = task
        await task.value
        tasks[recordID] = nil
    }

    /// The download itself. Progress is awaited in order (no unstructured
    /// hop), and the store ignores anything that arrives for a record that
    /// is no longer in flight.
    private static func run(
        _ item: DriveItem, recordID: UUID, adapter: DriveDownloadAdapter,
        destination: URL, activity: TransferActivityStore
    ) async {
        do {
            if item.isFolder {
                let urls = try await adapter.downloadTree(
                    shareID: item.shareID, linkID: item.id, destination: destination
                )
                activity.downloadFinished(
                    id: recordID, fileCount: urls.count, destination: destination
                )
            } else {
                let file = try await adapter.downloadSingleFile(
                    shareID: item.shareID, linkID: item.id, directory: destination
                ) { [weak activity] done, total in
                    await activity?.downloadProgress(
                        id: recordID, fraction: total > 0 ? Double(done) / Double(total) : 1
                    )
                }
                // Reveal the FILE itself (not its folder) — matches Finder's
                // "Reveal in Finder" expectation for single-file downloads.
                activity.downloadFinished(
                    id: recordID, fileCount: 1, destination: destination, reveal: file
                )
            }
        } catch {
            if Task.isCancelled || DownloadRecord.isCancellation(error) {
                activity.downloadCancelled(id: recordID)
            } else {
                activity.downloadFailed(id: recordID, error: error)
            }
        }
    }
}
