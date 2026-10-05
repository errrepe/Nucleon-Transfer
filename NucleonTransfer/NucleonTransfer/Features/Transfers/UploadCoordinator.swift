// Nucleon Transfer — upload orchestration for the browser (F7 S3.1).
// Owns the TransferQueue's live wiring for the session (uploader +
// snapshot listener) and the intake path for drops/panel picks into the
// CURRENT folder — unlike the legacy sheet, the destination is the
// DriveLocation the user is looking at, not a share picker.
// Post-operation consistency: enqueueTree creates remote folders and a
// finished job mutates its remote parent — both publish the touched
// linkIDs via TransferActivityStore.remoteChanged so the browser marks
// just those folders stale. `presentTransfers` flips on intake so the
// S3.2 popover can open on the first upload.
import Foundation
import UniformTypeIdentifiers

@MainActor
@Observable
final class UploadCoordinator {
    /// Queue snapshot for the transfers panel (S3.2 renders this).
    private(set) var jobs: [TransferJob] = []
    /// Job ID → breadcrumb ("My Files › Projects") captured at enqueue
    /// time, in-memory only — the coordinator has no listing context, so
    /// the caller computes the label. Jobs restored from disk (pre-relaunch)
    /// simply have no label.
    private(set) var destinationNames: [UUID: String] = [:]
    /// True while the intake scan/enqueue loop is running.
    private(set) var isAdding = false
    /// Last intake failure, already mapped through UserFacingError
    /// (S3.2's panel surfaces it; nil = none).
    private(set) var lastError: String?

    private let queue: TransferQueue
    private let drive: DriveClient
    private let addressKeys: [KeyringCache.UnlockedKey]
    private let resolver: NodeKeyResolver
    private let activity: TransferActivityStore
    private var started = false
    private var knownDone: Set<UUID> = []

    init(
        queue: TransferQueue,
        drive: DriveClient,
        addressKeys: [KeyringCache.UnlockedKey],
        resolver: NodeKeyResolver,
        activity: TransferActivityStore
    ) {
        self.queue = queue
        self.drive = drive
        self.addressKeys = addressKeys
        self.resolver = resolver
        self.activity = activity
    }

    /// Idempotent: wires the live uploader, subscribes snapshots, pumps.
    /// Same wiring the retired queue view-model used, plus the S3.1
    /// hook: a job reaching `.done` changed its remote parent, so the
    /// touched linkIDs publish via `remoteChanged` (browser reloads only
    /// the folders on screen — no polling, no global refresh).
    func start() async {
        if !started {
            started = true
            await queue.setUploader(
                DriveUploadAdapter(drive: drive, addressKeys: addressKeys, resolver: resolver)
            )
            await queue.setListener { [weak self] snap in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.jobs = snap
                    let doneNow = Set(snap.filter { $0.state == .done }.map(\.id))
                    let newDone = doneNow.subtracting(self.knownDone)
                    if !newDone.isEmpty {
                        let parents = snap.filter { newDone.contains($0.id) }
                            .map(\.parentLinkID)
                        self.activity.remoteChanged(parentLinkIDs: parents)
                    }
                    self.knownDone = doneNow
                }
            }
            await queue.start()
        }
        jobs = await queue.snapshot()
        knownDone = Set(jobs.filter { $0.state == .done }.map(\.id))
    }

    /// Detaches the snapshot listener (sign-out). AppSession pauses the
    /// queue and drops the uploader before calling this.
    func stop() async {
        await queue.setListener(nil)
        await queue.flush()
    }

    /// Writes any coalesced (not yet saved) queue change to disk now
    /// (F8.2-R2). The app also flushes the queue itself on quit.
    func flush() async {
        await queue.flush()
    }

    // MARK: - intake

    /// Enqueues `urls` (files and/or folders, structure preserved) under
    /// `destination` — the folder on screen, not a share root. Same
    /// semantics as the legacy `add(urls:)`: the security-scope grant is
    /// held for the session, the directory scan runs in a detached task
    /// off the main executor, and each file gets a best-effort
    /// security-scoped bookmark. `breadcrumb` is the caller-computed
    /// "My Files › Projects" label stored in `destinationNames`.
    func upload(urls: [URL], to destination: DriveLocation, breadcrumb: String) async {
        guard !urls.isEmpty else { return }
        isAdding = true
        defer { isAdding = false }
        lastError = nil
        for url in urls {
            // Scoped access must be held on the MainActor before the worker
            // reads; the queue persists bookmarks for later reads, so the
            // grant is intentionally held for the session (see audit note).
            _ = url.startAccessingSecurityScopedResource() // held for the session
            do {
                var isDir: ObjCBool = false
                let isDirectory = FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir)
                    && isDir.boolValue
                // Scan + bookmark creation are synchronous disk I/O: keep
                // them off the MainActor so large trees don't freeze the UI.
                // Bookmarks are made here, during the scan, so the queue
                // gets ONE batch enqueue (F8.2-R2 — per-file setBookmark
                // saves made big drops quadratic).
                let entries: [LocalTreeScan.Entry] = try await Task.detached(priority: .userInitiated) {
                    let scanned: [LocalTreeScan.Entry]
                    if isDirectory {
                        scanned = try LocalTreeScan.collect(root: url).entries
                    } else {
                        scanned = [LocalTreeScan.Entry(
                            url: url,
                            relativePath: url.lastPathComponent.precomposedStringWithCanonicalMapping,
                            isDirectory: false,
                            size: (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
                        )]
                    }
                    return LocalTreeScan.attachingBookmarks(scanned)
                }.value
                let adapter = DriveUploadAdapter(drive: drive, addressKeys: addressKeys, resolver: resolver)
                let ids = try await queue.enqueueTree(
                    entries: entries,
                    shareID: destination.shareID,
                    rootParentLinkID: destination.linkID,
                    folders: adapter
                )
                for id in ids { destinationNames[id] = breadcrumb }
                // Folder creation happened inside enqueueTree (parent→child):
                // the remote tree changed under the destination.
                activity.remoteChanged(parentLinkIDs: [destination.linkID])
                activity.presentTransfers = true
            } catch {
                lastError = "\(url.lastPathComponent): \(UserFacingError.message(for: error))"
            }
        }
        jobs = await queue.snapshot()
    }

    /// Provider → file URLs (the drop-intake logic the retired queue
    /// sheet used — moved here so the folder-table drop and the upload
    /// picker share one implementation).
    static func droppedFileURLs(_ providers: [NSItemProvider]) async -> [URL] {
        var urls: [URL] = []
        for provider in providers {
            guard provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) else { continue }
            if let item = try? await provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier),
               let url = (item as? URL) ?? (item as? NSURL as URL?) {
                urls.append(url)
            }
        }
        return urls
    }

    // MARK: - operators (thin pass-through + snapshot refresh)

    func pause(_ id: UUID) async { await queue.pause(id: id); jobs = await queue.snapshot() }
    func resume(_ id: UUID) async { await queue.resume(id: id); jobs = await queue.snapshot() }
    func cancel(_ id: UUID) async { await queue.cancel(id: id); jobs = await queue.snapshot() }
    func relaunch(_ id: UUID) async { await queue.relaunch(id: id); jobs = await queue.snapshot() }
    func remove(_ id: UUID) async {
        await queue.remove(id: id)
        destinationNames[id] = nil
        jobs = await queue.snapshot()
    }
    func relaunchAllFailed() async { await queue.relaunchAllFailed(); jobs = await queue.snapshot() }
    func pauseAll() async { await queue.pauseAll(); jobs = await queue.snapshot() }
}
