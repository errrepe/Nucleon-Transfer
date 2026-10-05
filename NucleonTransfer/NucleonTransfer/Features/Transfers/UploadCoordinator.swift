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
    /// Drop-level security grants still needed by unfinished jobs
    /// (F8.2-R4). Released as soon as all of a drop's jobs finish — jobs
    /// read through their own bookmarks (LocalFileAccess), so nothing has
    /// to stay open for the whole session any more.
    @ObservationIgnored private var grants = UploadGrantLedger<DropGrant>()

    /// One `startAccessingSecurityScopedResource()` call (the same URL
    /// dropped twice is two grants, each stopped once).
    private struct DropGrant: Hashable, Sendable {
        let token = UUID()
        let url: URL
    }

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
                    self.releaseFinishedGrants(in: snap)
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
        for grant in grants.releaseAll() { grant.url.stopAccessingSecurityScopedResource() }
    }

    /// Stops the drop grants whose jobs are all finished (F8.2-R4).
    private func releaseFinishedGrants(in snapshot: [TransferJob]) {
        guard !grants.isEmpty else { return }
        for grant in grants.releasable(in: snapshot) {
            grant.url.stopAccessingSecurityScopedResource()
        }
    }

    /// Writes any coalesced (not yet saved) queue change to disk now
    /// (F8.2-R2). The app also flushes the queue itself on quit.
    func flush() async {
        await queue.flush()
    }

    // MARK: - intake

    /// Enqueues `urls` (files and/or folders, structure preserved — a
    /// dropped folder keeps its own top-level folder, F8.2-R6) under
    /// `destination` — the folder on screen, not a share root. The
    /// security-scope grant is held until this drop's jobs finish
    /// (F8.2-R4), the directory scan runs in a detached task off the main
    /// executor, and each file gets a best-effort security-scoped bookmark. `breadcrumb` is the caller-computed
    /// "My Files › Projects" label stored in `destinationNames`.
    func upload(urls: [URL], to destination: DriveLocation, breadcrumb: String) async {
        guard !urls.isEmpty else { return }
        isAdding = true
        defer { isAdding = false }
        lastError = nil
        for url in urls {
            // Scoped access must be held before the detached scan reads
            // and creates bookmarks. It is kept only until this drop's jobs
            // finish (F8.2-R4) — each job then reads through its own
            // bookmark + scope (LocalFileAccess), also after a relaunch.
            let granted = url.startAccessingSecurityScopedResource()
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
                        // F8.2-R6: the dropped folder itself is preserved —
                        // "Vacation" lands as Vacation/… in the destination.
                        scanned = LocalTreeScan.rooted(
                            try LocalTreeScan.collect(root: url).entries,
                            rootName: url.lastPathComponent
                        )
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
                if granted {
                    if ids.isEmpty {
                        url.stopAccessingSecurityScopedResource()
                    } else {
                        grants.hold(DropGrant(url: url), for: ids)
                    }
                }
                for id in ids { destinationNames[id] = breadcrumb }
                // Folder creation happened inside enqueueTree (parent→child):
                // the remote tree changed under the destination.
                activity.remoteChanged(parentLinkIDs: [destination.linkID])
                activity.presentTransfers = true
            } catch {
                if granted { url.stopAccessingSecurityScopedResource() }
                lastError = "\(url.lastPathComponent): \(UserFacingError.message(for: error))"
            }
        }
        jobs = await queue.snapshot()
        // Jobs that already finished before their grant was recorded.
        releaseFinishedGrants(in: jobs)
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
