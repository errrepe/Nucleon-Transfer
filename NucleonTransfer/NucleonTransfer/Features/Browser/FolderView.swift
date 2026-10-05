// Nucleon Transfer — one folder screen in the browser stack (F7 S2.2–S3.1).
// FolderTable plus the spec-6.4 overlay states (loading / empty / filtered
// / error), the window title + item-count subtitle, the title-menu
// breadcrumb and the Photos read-only banner. S2.3 added the action toolbar
// (New Folder / Download / Trash / Reload), the New Folder sheet, the
// trash confirmationDialog and the action-error alert — presentation flags
// live on BrowserModel so the table's context menu can trigger them too.
// S3.1 adds the Upload menu + drop-to-upload (DropOverlay while targeted).
// F7.1 R5 feeds the New Folder sheet the decrypted sibling names for its
// live duplicate check. Loading kicks off in .task(id:) so revisits are
// cheap (cache hit in BrowserModel.load).
// F8.4-U1: after a Proton 2000 upload refusal, one dismissible banner
// joins the top inset and the Upload menu + drop target disable.
// F8.4-U3: the sheet / trash dialog / error alert moved up to
// BrowserContainerView (one presentation, bound to `model.current`); the
// toolbar is grouped with fixed spacers ({Upload, New Folder}, {Download,
// Trash}, Transfers) and Reload lives in the Go menu (⌘R), like Finder;
// Back/Forward sit in the navigation area; a failed refresh over cached
// rows shows the "Couldn't refresh" banner; the subtitle counts the
// selection.
// Polish pass: banners slide in under the toolbar, the overlay states
// crossfade, the spinner waits a beat before showing (no flash on fast
// loads) and the subtitle stays blank until there is a count to show.
import SwiftUI
import UniformTypeIdentifiers

struct FolderView: View {
    let location: DriveLocation

    /// Passed in by BrowserContainerView — never read from the environment.
    /// A pushed FolderView lives in navigationDestination content, which an
    /// object injected outside the NavigationStack does not reliably reach
    /// (crash B1: EnvironmentValues assert). @Bindable keeps the $model.*
    /// bindings the toolbar, sheet and dialogs use.
    @Bindable var model: BrowserModel
    /// Column widths/visibility/order, owned by BrowserContainerView's
    /// @SceneStorage (F8.4-U4) — one value for every folder in the stack.
    @Binding var columnCustomization: TableColumnCustomization<DriveItem>
    /// The container's filter-field focus (published to the menu bar so
    /// ⌘⌫ stays delete-to-line-start while typing).
    var isSearchFocused: FocusState<Bool>.Binding
    /// True while a file drag hovers the table — drives DropOverlay.
    @State private var isTargeted = false
    /// The row under the pointer, written by FolderTable — while a drag
    /// hovers a folder row the overlay names THAT destination (B10).
    /// F8.3-P3: an observable object, read only inside `HoveredDropOverlay`,
    /// so pointer moves never re-evaluate this body.
    @State private var hover = RowHoverState()
    /// View ▸ Show Path Bar (⌥⌘P) — drawn per folder view, so pushed
    /// folders show it too.
    @AppStorage(BrowserPreferences.showPathBarKey) private var showPathBar = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Toolbar symbol beats (polish pass 4): Trash shows `trash.fill`,
    /// New Folder morphs to a filled folder, Download erases its arrow
    /// (drawn back on when the flag drops).
    @State private var trashJustFilled = false
    @State private var folderJustCreated = false
    @State private var downloadArrowErased = false

    /// This folder's store — observed per folder (F8.3-P3).
    private var state: FolderStore { model.state(for: location) }
    /// Memoized: recomputed only when the rows, sort or filter change.
    private var items: [DriveItem] { model.visibleItems(for: location) }

    var body: some View {
        // Banners and the path bar are stacked around the table, not set
        // as safe-area insets on it: an inset that appears and goes away
        // (the uploads-blocked banner after a drop, then dismissed) shifts
        // the table's NSScrollView, and its scroll offset stayed displaced
        // under the toolbar with no way to scroll back (live check).
        VStack(spacing: 0) {
            banners
            tableWithUploadDrop
            if showPathBar {
                PathBar(model: model, location: location)
                    .transition(.opacity)
            }
        }
            .animation(Motion.adaptive(Motion.smooth, reduceMotion: reduceMotion), value: bannerState)
            .animation(Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion), value: showPathBar)
            // The topmost FolderView owns the toolbar, so the filter field
            // is declared here (a stack-level .searchable never showed).
            .searchable(
                text: $model.filterText,
                placement: .toolbar,
                prompt: "Filter this folder"
            )
            .searchFocused(isSearchFocused)
            .navigationTitle(location.name)
            .navigationSubtitle(subtitle)
            // The stack's own back chevron is replaced by the Finder-style
            // Back/Forward group below (F8.4-U3).
            .navigationBarBackButtonHidden(true)
            .toolbarTitleMenu {
                // Finder-style: current folder first, root last.
                ForEach(model.ancestors(of: location).reversed(), id: \.self) { ancestor in
                    Button(ancestor.name) { model.pop(to: ancestor) }
                }
            }
            .toolbar {
                // F8.4-U3: Back/Forward (⌘[ / ⌘]), Finder's navigation
                // group. The folder stack is the history, so Back pops.
                ToolbarItem(placement: .navigation) {
                    ControlGroup {
                        Button("Back", systemImage: "chevron.backward") { model.goBack() }
                            .help("See folders you viewed previously")
                            .disabled(!model.canGoBack)
                        Button("Forward", systemImage: "chevron.forward") { model.goForward() }
                            .help("See folders you viewed next")
                            .disabled(!model.canGoForward)
                    }
                    .controlGroupStyle(.navigation)
                }
                // Spec-6.2 order, grouped (F8.4-U3): {Upload, New Folder},
                // {Download, Trash}, then the S3.2 Transfers popover.
                // Reload is in Go ▸ Reload (⌘R) and the empty-area context
                // menu. All act on `model.current` — the topmost
                // FolderView owns the toolbar.
                ToolbarItem(placement: .primaryAction) {
                    Menu("Upload", systemImage: "arrow.up.doc") {
                        Button("Upload Files…") {
                            Task { await model.uploadPanel(folders: false) }
                        }
                        Button("Upload Folder…") {
                            Task { await model.uploadPanel(folders: true) }
                        }
                    }
                    .help(uploadHelp)
                    .disabled(!model.canUpload)
                    // Polish pass 4: each toolbar symbol answers its action
                    // with its own gesture — Upload's arrow leans up,
                    // Download's is redrawn, New Folder fills, Trash fills
                    // and shakes. A refused upload wiggles sideways like
                    // the blocked banner's icon.
                    .symbolEffect(.wiggle.up, options: Motion.symbolOptions,
                                  value: pulse(model.toolbarPulses.uploads))
                    .symbolEffect(.wiggle, options: Motion.symbolOptions,
                                  value: pulse(model.uploadRefusedCount))
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        model.showingNewFolder = true
                    } label: {
                        // The "+" melts into a filled folder for a beat.
                        Label("New Folder", systemImage: folderJustCreated ? "folder.fill" : "folder.badge.plus")
                            .contentTransition(symbolSwap)
                    }
                    .help("New Folder")
                    .disabled(!model.root.allowsWrites)
                }
                ToolbarSpacer(.fixed, placement: .primaryAction)
                ToolbarItem(placement: .primaryAction) {
                    Button("Download", systemImage: "arrow.down.circle") {
                        model.downloadItems(model.selection)
                    }
                    .help("Download")
                    .disabled(model.selection.isEmpty)
                    .symbolEffect(.drawOff, options: Motion.symbolOptions, isActive: downloadArrowErased)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        model.requestTrash(model.selection)
                    } label: {
                        // The can fills and shakes as the rows leave.
                        Label("Move to Trash", systemImage: trashJustFilled ? "trash.fill" : "trash")
                            .contentTransition(symbolSwap)
                    }
                    .symbolEffect(.wiggle.counterClockwise, options: Motion.symbolOptions,
                                  value: pulse(model.toolbarPulses.trashes))
                    .help("Move to Trash")
                    .disabled(model.selection.isEmpty || !model.root.allowsWrites)
                }
                ToolbarSpacer(.fixed, placement: .primaryAction)
                ToolbarItem(placement: .primaryAction) {
                    // S3.2: transfers popover — badge counts in-flight items.
                    // R2/B1: session by parameter — toolbar items of a
                    // pushed FolderView are another environment blind spot.
                    TransfersToolbarButton(session: model.session)
                }
            }
            .task(id: location) {
                await model.load(location)
            }
            .task(id: model.toolbarPulses.trashes) {
                guard model.toolbarPulses.trashes > 0 else { return }
                await beat($trashJustFilled)
            }
            .task(id: model.toolbarPulses.foldersCreated) {
                guard model.toolbarPulses.foldersCreated > 0 else { return }
                await beat($folderJustCreated)
            }
            .task(id: model.toolbarPulses.downloads) {
                // Movement-only (the arrow is erased and redrawn).
                guard model.toolbarPulses.downloads > 0, !reduceMotion else { return }
                await beat($downloadArrowErased, for: .milliseconds(600))
            }
    }

    /// Symbol swaps: magic replace (shared parts morph), a crossfade under
    /// Reduce Motion.
    private var symbolSwap: ContentTransition {
        reduceMotion ? .opacity : .symbolEffect(.replace.magic(fallback: .replace), options: Motion.symbolOptions)
    }

    /// Raises `flag` for `duration`, then drops it — a toolbar symbol
    /// beat. A newer beat cancels this one (the task restarts), so the
    /// flag drops early and rises again.
    private func beat(_ flag: Binding<Bool>, for duration: Duration = Motion.symbolBeat) async {
        flag.wrappedValue = true
        try? await Task.sleep(for: duration)
        flag.wrappedValue = false
    }

    /// A symbol-effect trigger: the counter, or a constant under Reduce
    /// Motion (bounce and wiggle are movement).
    private func pulse(_ counter: Int) -> Int {
        reduceMotion ? 0 : counter
    }

    /// Read-only (Photos), uploads-blocked and refresh-failed banners.
    @ViewBuilder
    private var banners: some View {
        if model.root.kind == .photos {
            PhotosReadOnlyBanner()
        }
        if model.showsUploadsBlockedBanner {
            UploadsBlockedBanner(refusals: model.uploadRefusedCount) {
                model.dismissUploadsBlockedBanner()
            }
                .transition(Motion.banner(reduceMotion: reduceMotion))
        }
        if case .failed(let message) = state.phase, !state.items.isEmpty {
            RefreshFailedBanner(message: message) {
                Task { await model.load(location, force: true) }
            }
            .transition(Motion.banner(reduceMotion: reduceMotion))
        }
    }

    /// What the animated banners depend on — one value, so the stack
    /// animates only when a banner comes or goes.
    private var bannerState: [Bool] {
        var refreshFailed = false
        if case .failed = state.phase, !state.items.isEmpty { refreshFailed = true }
        return [model.showsUploadsBlockedBanner, refreshFailed]
    }

    /// The listing with the S3.1 drop-to-upload wiring. On read-only
    /// roots (Photos) the modifier is omitted entirely: no highlight and
    /// the drop is refused — there is nothing to accept it onto.
    /// `model.root` is fixed for the view's lifetime (`.id(root.id)`
    /// rebuilds the stack on root change), so the conditional is stable.
    /// B10: the destination is this view's `location`, pinned at drop
    /// time — a folder-row drop (FolderTable) uploads into that row's
    /// folder, and `location` never moves with `model.current`, so
    /// navigating while the providers resolve can't retarget the upload.
    @ViewBuilder
    private var tableWithUploadDrop: some View {
        let table = FolderTable(
            items: items, location: location, model: model, hover: hover,
            columnCustomization: $columnCustomization
        )
            // Banner/path-bar animations wrap this stack; a refresh that
            // swaps the rows in the same update (Try Again on the
            // "Couldn't refresh" banner) must not animate a 5k-row diff.
            // Only deliberate row changes (Motion.rowChange) get through.
            .transaction { if !$0.animatesRows { $0.animation = nil } }
            .overlay {
                stateOverlay
                    .animation(Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion), value: overlayState)
            }
            .overlay {
                // The animation sits inside the overlay so it never reaches
                // the table's rows (see FolderTable's transaction below).
                ZStack {
                    if isTargeted {
                        HoveredDropOverlay(hover: hover, fallback: location)
                            .transition(
                                reduceMotion ? .opacity : .opacity.combined(with: .scale(scale: 1.02))
                            )
                    }
                }
                .animation(Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion), value: isTargeted)
            }
        if model.root.allowsWrites {
            // F8.4-U1: drops stay accepted while uploads are blocked — a
            // refused drag gave no feedback; BrowserModel.upload brings
            // the banner back instead.
            table.onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
                Task {
                    let urls = await UploadCoordinator.droppedFileURLs(providers)
                    await model.upload(urls: urls, to: location)
                }
                return true
            }
        } else {
            table
        }
    }

    /// Spec-6.4 states, drawn over the table. Cached rows stay visible
    /// through reloads and failed refreshes — the blocking states only
    /// appear when there is nothing on screen.
    @ViewBuilder
    private var stateOverlay: some View {
        switch state.phase {
        case .loading where state.items.isEmpty:
            DelayedProgressView(title: "Loading…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .transition(.opacity)
        case .failed(let message) where state.items.isEmpty:
            ContentUnavailableView {
                Label("Couldn't Load Folder", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Try Again") {
                    Task { await model.load(location, force: true) }
                }
            }
            .transition(overlayTransition)
        case .loaded where state.items.isEmpty:
            // B3: the copy follows the root. Photos is read-only, so it
            // must not invite uploads; a non-writable non-Photos root
            // (none today — ShareCatalog only yields main/photos/device)
            // keeps the plain title. Computers are writable → same copy
            // as My Files.
            if model.root.kind == .photos {
                ContentUnavailableView(
                    "No Photos",
                    systemImage: "photo.on.rectangle",
                    description: Text("Photos you add in Proton Drive appear here.")
                )
                .transition(overlayTransition)
            } else if model.root.allowsWrites {
                ContentUnavailableView(
                    "This Folder Is Empty",
                    systemImage: "folder",
                    description: Text("Drop files here or use Upload.")
                )
                .transition(overlayTransition)
            } else {
                ContentUnavailableView("This Folder Is Empty", systemImage: "folder")
                    .transition(overlayTransition)
            }
        case _ where items.isEmpty && isFiltering:
            ContentUnavailableView.search(text: model.filterText)
                .transition(.opacity)
        default:
            EmptyView()
        }
    }

    /// Which overlay state is up — drives its crossfade. The search text
    /// is left out so typing doesn't re-animate the "No Results" view.
    private var overlayState: Int {
        switch state.phase {
        case .loading where state.items.isEmpty: 1
        case .failed where state.items.isEmpty: 2
        case .loaded where state.items.isEmpty: 3
        case _ where items.isEmpty && isFiltering: 4
        default: 0
        }
    }

    /// Empty/error states rise slightly into place.
    private var overlayTransition: AnyTransition {
        reduceMotion ? .opacity : .opacity.combined(with: .scale(scale: 0.96))
    }

    /// "2 of 14 selected" / "14 items" (F8.4-U3). Counts selected rows
    /// among the visible ones, so a filter never yields "3 of 2". Blank
    /// while the first load runs or failed — "0 items" over a spinner or
    /// an error read as an empty folder (live audit).
    private var subtitle: String {
        if state.items.isEmpty, state.phase != .loaded { return "" }
        let selection = model.selection
        let selected = selection.isEmpty ? 0 : items.lazy.filter { selection.contains($0.id) }.count
        return DriveFormatting.subtitle(selected: selected, total: items.count)
    }

    /// Tooltip for the Upload menu: why it's disabled, when it is.
    private var uploadHelp: Text {
        if !model.root.allowsWrites { return Text("Uploading to Photos isn't supported yet.") }
        if model.uploadsBlocked { return Text(UploadsBlockedCopy.message) }
        return Text("Upload files or a folder into this folder.")
    }

    private var isFiltering: Bool {
        !model.filterText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

/// The drop overlay bound to the hovered row (B10). Its own view so the
/// `hover.item` read — which changes on every row crossed — invalidates
/// only this overlay, and only while a drag is targeted.
private struct HoveredDropOverlay: View {
    let hover: RowHoverState
    let fallback: DriveLocation

    var body: some View {
        let destination = DropTargeting.destination(for: hover.item, fallback: fallback)
        DropOverlay(location: destination)
            // Trackpad "snap" as the drop target moves onto a folder row
            // (or back to this folder) — the HIG's alignment case, and the
            // app's only haptic. Follows the system haptics setting.
            .sensoryFeedback(.alignment, trigger: destination)
    }
}
