// Nucleon Transfer — folder browser state for one drive root (F7 S2.2).
// Owns the NavigationStack path, a per-folder listing cache, selection,
// sort order and the filter text. All network + name decryption stays
// inside the DriveListing actor; this model only reorders and caches the
// already-decrypted rows, so no CPU work ever runs on the main executor.
// Nothing is persisted to disk — the cache dies with the view.
import Foundation

@MainActor
@Observable
final class BrowserModel {
    enum LoadPhase: Equatable {
        case idle, loading, loaded, failed(String)
    }

    /// Cached listing for one folder, keyed by folder linkID. Old rows stay
    /// visible while `phase == .loading` so reloads never blank the table.
    struct FolderState {
        var items: [DriveItem] = []
        var phase: LoadPhase = .idle
        /// Set by `markStale` after an app operation touched the folder;
        /// the next `load` refetches instead of serving the cache.
        var isStale = false
    }

    let root: DriveRoot
    /// Synthetic location for the root folder; `name` is the classified
    /// display name ("My Files", "Photos", "Computer N") so the title and
    /// breadcrumb read like the sidebar.
    let rootLocation: DriveLocation
    /// Pushed folders — bound directly to the NavigationStack. Clears the
    /// selection on every change (forward, back, breadcrumb jump).
    var path: [DriveLocation] = [] {
        didSet { selection = [] }
    }
    /// Where the window is right now: deepest pushed folder, or the root.
    var current: DriveLocation { path.last ?? rootLocation }
    private(set) var folders: [String: FolderState] = [:] // by folder linkID
    var selection: Set<DriveItem.ID> = []
    var sortOrder: [KeyPathComparator<DriveItem>] = [
        KeyPathComparator(\.name, comparator: .localizedStandard)
    ]
    var filterText = ""

    // MARK: - S2.3 action UI state

    /// Drives the New Folder sheet (toolbar + empty-area context menu).
    var showingNewFolder = false
    /// Drives the "Move to Trash" confirmationDialog (toolbar + menu).
    /// Set through `requestTrash(_:)` so `pendingTrash` is always filled.
    var confirmingTrash = false
    /// The items the open trash confirmation will act on (F8.2-R8). The
    /// context menu passes the CLICKED rows — right-clicking an unselected
    /// row doesn't move the selection on macOS — while the toolbar and ⌘⌫
    /// pass the selection. The dialog counts and trashes exactly this set;
    /// cleared on confirm/cancel.
    var pendingTrash: Set<DriveItem.ID> = []
    /// Message for the action-failure alert (trash/create); nil = hidden.
    var actionError: String?
    /// Mirrors the activity store's remote-changed token so views can key
    /// `.task(id:)` on it without touching AppSession (tracking flows
    /// through @Observable property access).
    var remoteChangedToken: Int { session.activity.remoteChangedToken }

    /// The session this browser belongs to — also re-injected into the
    /// environment by BrowserContainerView so children (e.g. the S3.2
    /// transfers button) see the same instance, previews included.
    let session: AppSession
    /// Orders overlapping listings and hides optimistic removals (F8.2-R7).
    @ObservationIgnored private var loadGate = FolderLoadGate()
    /// DEBUG preview seam: when true, `load` is a no-op so seeded folder
    /// states render offline (see `BrowserModel.preview` below).
    private var previewStubbed = false

    init(root: DriveRoot, session: AppSession) {
        self.root = root
        self.session = session
        rootLocation = DriveLocation(
            shareID: root.shareID,
            linkID: root.rootLinkID,
            name: root.displayName
        )
    }

    /// Breadcrumb chain from the root down to (and including) `location`.
    /// Unknown locations degrade to root + location so the menu never
    /// renders empty.
    func ancestors(of loc: DriveLocation) -> [DriveLocation] {
        if loc == rootLocation { return [rootLocation] }
        guard let index = path.firstIndex(of: loc) else {
            return [rootLocation, loc]
        }
        return [rootLocation] + Array(path.prefix(through: index))
    }

    /// Cached state for `loc`, or an empty idle state when never loaded.
    func state(for loc: DriveLocation) -> FolderState {
        folders[loc.linkID] ?? FolderState()
    }

    /// Rows for `loc` after the search filter and the Table sort order.
    func visibleItems(for loc: DriveLocation) -> [DriveItem] {
        DriveItemOrdering.sorted(
            DriveItemOrdering.filtered(state(for: loc).items, query: filterText),
            using: sortOrder
        )
    }

    /// Fetches `loc`'s children into the cache. Skips the network when the
    /// folder is already `loaded`, unless `force` or the stale flag says the
    /// contents may have changed. Keeps the previous rows on screen while
    /// the refresh is in flight (no flicker). A `401` means the session is
    /// gone → sign out so the whole app returns to the login screen.
    /// F8.2-R7: overlapping loads of one folder are ordered by `loadGate` —
    /// only the latest request applies its result, optimistic trash
    /// removals stay hidden from listings that predate them, and the
    /// state is re-read after the await (a stale flag set meanwhile
    /// survives, so the next visit refetches).
    func load(_ loc: DriveLocation, force: Bool = false) async {
        if previewStubbed { return }
        let cached = state(for: loc)
        if cached.phase == .loaded, !force, !cached.isStale { return }
        let token = loadGate.begin(folder: loc.linkID)
        var starting = cached
        starting.phase = .loading
        starting.isStale = false
        folders[loc.linkID] = starting
        guard let listing = session.listing else {
            folders[loc.linkID]?.phase = .failed("Session not ready. Sign in again.")
            return
        }
        do {
            let items = try await listing.children(of: loc)
            // Sign-out mid-flight replaced/nilled the listing: drop the
            // result instead of showing another session's data.
            guard session.listing === listing,
                  let visible = loadGate.apply(items, token: token, folder: loc.linkID)
            else { return }
            var state = state(for: loc)
            state.items = visible
            state.phase = .loaded
            folders[loc.linkID] = state
        } catch let error as ProtonAPIError where error == .unauthorized {
            // Only the session that produced this listing may be signed
            // out — a late 401 from an old session must not end a new one.
            guard session.listing === listing else { return }
            await session.signOut(reason: "Your session expired. Sign in again.")
        } catch {
            guard session.listing === listing,
                  loadGate.isCurrent(token, folder: loc.linkID)
            else { return }
            folders[loc.linkID, default: FolderState()].phase =
                .failed(UserFacingError.message(for: error))
        }
    }

    /// Primary activation (double click / Open). Folders push onto the
    /// navigation path; files download via the session coordinator (S2.3).
    func open(_ item: DriveItem) {
        if item.isFolder {
            path.append(item.location)
        } else {
            downloadItems([item.id])
        }
    }

    /// Double-click activation on the current selection. In-place
    /// navigation can only go one way, so the first selected folder wins;
    /// a file downloads the whole selected set.
    func openSelection(_ ids: Set<DriveItem.ID>) {
        for item in visibleItems(for: current) where ids.contains(item.id) {
            if item.isFolder {
                path.append(item.location)
                return
            }
            downloadItems(ids)
            return
        }
    }

    /// Back one level (bound to nothing yet — the NavigationStack back
    /// button already pops `path`; kept for keyboard/menu wiring).
    func goToParent() {
        if !path.isEmpty { path.removeLast() }
    }

    /// Breadcrumb jump: pops the path back to `loc` (root = pop everything).
    /// Unknown locations leave the path untouched.
    func pop(to loc: DriveLocation) {
        if loc == rootLocation {
            path.removeAll()
        } else if let index = path.lastIndex(of: loc) {
            path.removeLast(path.count - index - 1)
        }
    }

    /// Explicit user reload of the visible folder — always refetches.
    func reloadCurrent() async {
        await load(current, force: true)
    }

    /// Post-operation consistency (uploads/deletes in S2.3): flags every
    /// touched parent as stale, and refetches only if one of them is the
    /// folder on screen. Other stale folders lazily refresh on next visit.
    func markStale(parentLinkIDs: Set<String>) {
        for linkID in parentLinkIDs {
            folders[linkID]?.isStale = true
        }
        guard parentLinkIDs.contains(current.linkID) else { return }
        Task { await load(current) }
    }

    // MARK: - S2.3 actions

    /// Called when `remoteChangedToken` bumps (create/trash/upload touched
    /// remote parents): forwards the published set to `markStale`.
    func observeRemoteChanges() {
        markStale(parentLinkIDs: session.activity.remoteChangedParents)
    }

    /// Selected items in the CURRENT folder (cache, not the filtered view —
    /// a row hidden by the search filter is still a real selection).
    func selectedItems(_ ids: Set<DriveItem.ID>) -> [DriveItem] {
        state(for: current).items.filter { ids.contains($0.id) }
    }

    /// Kicks a batch download through the session coordinator — it owns the
    /// destination panel, sequential loop and activity records. No-ops when
    /// signed out (downloads is nil) or the selection is empty.
    func downloadItems(_ ids: Set<DriveItem.ID>) {
        let items = selectedItems(ids)
        guard !items.isEmpty, let downloads = session.downloads else { return }
        Task { await downloads.download(items) }
    }

    /// Upload intake (S3.1): the shared files/folders picker, then enqueue
    /// into the current folder via the session's UploadCoordinator.
    /// No-ops on read-only roots (Photos) or when uploads aren't wired.
    func uploadPanel(folders: Bool) async {
        guard root.allowsWrites, session.uploads != nil else { return }
        let urls = await Panels.chooseUploadItems(folders: folders)
        await upload(urls: urls)
    }

    /// Enqueues dropped/picked URLs into `destination` (S3.1). B10: the
    /// caller pins the destination — a folder-row drop passes that row's
    /// location, the table-level drop and the pickers pass the open
    /// folder — so a mid-drop navigation can't retarget the upload.
    /// The breadcrumb ("My Files › Projects") is computed here — the
    /// coordinator only stores the label for the transfers panel; for a
    /// row folder off the navigation path `ancestors` degrades to
    /// root › row. Guards read-only roots so a stray drop on Photos
    /// never reaches the queue.
    func upload(urls: [URL], to destination: DriveLocation) async {
        guard root.allowsWrites, !urls.isEmpty, let uploads = session.uploads else { return }
        let breadcrumb = ancestors(of: destination).map(\.name).joined(separator: " › ")
        await uploads.upload(urls: urls, to: destination, breadcrumb: breadcrumb)
    }

    /// Uploads into the folder on screen — the pickers/menus that act on
    /// `current` (S3.1).
    func upload(urls: [URL]) async {
        await upload(urls: urls, to: current)
    }

    /// Creates a folder named `name` in the current folder, refetches it
    /// and selects the new row. Throws raw — the sheet maps via
    /// UserFacingError and stays open so the name can be fixed.
    /// (`folderOps.createFolder` already publishes remoteChanged; the
    /// extra forced load is a belt-and-braces refresh, `load` dedupes.)
    func createFolder(named name: String) async throws {
        guard let ops = session.folderOps else {
            throw FolderOperationError.sessionNotReady
        }
        let linkID = try await ops.createFolder(name: name, in: current)
        await load(current, force: true)
        selection = [linkID]
    }

    /// Opens the trash confirmation for `ids` (F8.2-R8). No-op on an empty
    /// set or a read-only root.
    func requestTrash(_ ids: Set<DriveItem.ID>) {
        guard !ids.isEmpty, root.allowsWrites else { return }
        pendingTrash = ids
        confirmingTrash = true
    }

    /// The dialog's destructive button: trashes `pendingTrash` and clears it.
    func confirmTrash() {
        let ids = pendingTrash
        pendingTrash = []
        Task { await trashItems(ids) }
    }

    /// The dialog's cancel path (button, Esc, click-away).
    func cancelTrash() {
        pendingTrash = []
    }

    /// Optimistic trash (S2.3/6.3): rows leave the cache immediately, then
    /// the batch endpoint runs; `remoteChanged` marks the parent stale →
    /// reload. A failure force-reloads (rows come back) and lands in
    /// `actionError` for the view's alert. F8.2-R7: the removal is
    /// registered with `loadGate`, so a listing requested before the
    /// trash landed can't bring the rows back.
    func trashItems(_ ids: Set<DriveItem.ID>) async {
        let items = selectedItems(ids)
        guard !items.isEmpty, let ops = session.folderOps else { return }
        let loc = current
        let removed = Set(items.map(\.id))
        let handle = loadGate.beginRemoval(removed, folder: loc.linkID)
        folders[loc.linkID]?.items.removeAll { removed.contains($0.id) }
        selection.subtract(ids)
        do {
            try await ops.trash(items, in: loc)
            loadGate.finishRemoval(handle, folder: loc.linkID, succeeded: true)
        } catch {
            loadGate.finishRemoval(handle, folder: loc.linkID, succeeded: false)
            await load(loc, force: true)
            actionError = UserFacingError.message(for: error)
        }
    }
}

#if DEBUG
extension BrowserModel {
    /// Preview seam: seeds the folder cache with fixture rows and freezes
    /// `load`, so every state renders offline. `.loading` + no items shows
    /// the spinner; `error` non-nil forces the retryable failure state.
    static func preview(
        root: DriveRoot = PreviewFixtures.roots.myFiles ?? DriveRoot(
            shareID: "share-main", rootLinkID: "link-main-root",
            volumeID: "vol-main", kind: .main, displayName: "My Files"
        ),
        items: [DriveItem] = PreviewFixtures.items,
        phase: LoadPhase = .loaded,
        error: String? = nil
    ) -> BrowserModel {
        let model = BrowserModel(root: root, session: PreviewFixtures.session())
        var state = FolderState()
        state.items = items
        if let error {
            state.phase = .failed(error)
        } else {
            state.phase = phase
        }
        model.folders[model.rootLocation.linkID] = state
        model.previewStubbed = true
        return model
    }
}
#endif
