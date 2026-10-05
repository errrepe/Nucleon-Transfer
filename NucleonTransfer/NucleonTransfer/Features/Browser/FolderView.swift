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
    /// True while a file drag hovers the table — drives DropOverlay.
    @State private var isTargeted = false
    /// The row under the pointer, mirrored from FolderTable — while a
    /// drag hovers a folder row the overlay names THAT destination (B10).
    @State private var hoveredItem: DriveItem?

    private var state: BrowserModel.FolderState { model.state(for: location) }
    private var items: [DriveItem] { model.visibleItems(for: location) }

    var body: some View {
        tableWithUploadDrop
            .safeAreaInset(edge: .top, spacing: 0) {
                if model.root.kind == .photos {
                    Label("Photos is read-only in Nucleon Transfer.", systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal)
                        .padding(.vertical, 8)
                        .background(.regularMaterial)
                }
            }
            .navigationTitle(location.name)
            .navigationSubtitle(DriveFormatting.itemCount(items.count))
            .toolbarTitleMenu {
                // Finder-style: current folder first, root last.
                ForEach(model.ancestors(of: location).reversed(), id: \.self) { ancestor in
                    Button(ancestor.name) { model.pop(to: ancestor) }
                }
            }
            .toolbar {
                // Spec-6.2 order: Upload, New Folder, Download, Trash,
                // Reload — then the S3.2 Transfers popover button. All
                // act on `model.current` — the topmost FolderView owns
                // the toolbar.
                ToolbarItem(placement: .primaryAction) {
                    Menu("Upload", systemImage: "arrow.up.doc") {
                        Button("Upload Files…") {
                            Task { await model.uploadPanel(folders: false) }
                        }
                        Button("Upload Folder…") {
                            Task { await model.uploadPanel(folders: true) }
                        }
                    }
                    .help(model.root.allowsWrites
                          ? "Upload files or a folder into this folder."
                          : "Uploading to Photos isn't supported yet.")
                    .disabled(!model.root.allowsWrites)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("New Folder", systemImage: "folder.badge.plus") {
                        model.showingNewFolder = true
                    }
                    .help("New Folder")
                    .disabled(!model.root.allowsWrites)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Download", systemImage: "arrow.down.circle") {
                        model.downloadItems(model.selection)
                    }
                    .help("Download")
                    .disabled(model.selection.isEmpty)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Move to Trash", systemImage: "trash") {
                        model.requestTrash(model.selection)
                    }
                    .help("Move to Trash")
                    .disabled(model.selection.isEmpty || !model.root.allowsWrites)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Reload", systemImage: "arrow.clockwise") {
                        Task { await model.reloadCurrent() }
                    }
                    .help("Reload")
                    .disabled(state.phase == .loading)
                }
                ToolbarItem(placement: .primaryAction) {
                    // S3.2: transfers popover — badge counts in-flight items.
                    // R2/B1: session by parameter — toolbar items of a
                    // pushed FolderView are another environment blind spot.
                    TransfersToolbarButton(session: model.session)
                }
            }
            .sheet(isPresented: $model.showingNewFolder) {
                NewFolderSheet(
                    // R5: live duplicate check against the decrypted
                    // sibling names — undecrypted items stay out and the
                    // server remains the safety net.
                    existingNames: Set(state.items.filter(\.isNameDecrypted).map(\.name))
                ) { name in
                    try await model.createFolder(named: name)
                }
            }
            // F8.2-R8: counts and trashes `pendingTrash` (the clicked rows
            // or the selection, whichever opened the dialog) — never the
            // live selection, which a context-menu click doesn't move.
            .confirmationDialog(
                "Move ^[\(model.pendingTrash.count) item](inflect: true) to Trash?",
                isPresented: $model.confirmingTrash,
                titleVisibility: .visible
            ) {
                Button("Move to Trash", role: .destructive) {
                    model.confirmTrash()
                }
                Button("Cancel", role: .cancel) {
                    model.cancelTrash()
                }
            } message: {
                Text("You can restore them from Trash in Proton Drive on the web.")
            }
            .alert(
                "Couldn’t Move to Trash",
                isPresented: Binding(
                    get: { model.actionError != nil },
                    set: { if !$0 { model.actionError = nil } }
                ),
                presenting: model.actionError
            ) { _ in
                Button("OK", role: .cancel) {}
            } message: { message in
                Text(message)
            }
            // S4.2: publish this browser to the menu bar (AppCommands).
            // Every FolderView in the stack shares the same model, so the
            // focused scene's value is unambiguous.
            .focusedSceneValue(\.browserModel, model)
            .task(id: location) {
                await model.load(location)
            }
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
        let table = FolderTable(items: items, model: model, hoveredItem: $hoveredItem)
            .overlay { stateOverlay }
            .overlay {
                if isTargeted {
                    DropOverlay(location: DropTargeting.destination(
                        for: hoveredItem, fallback: location))
                }
            }
        if model.root.allowsWrites {
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
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
            } else if model.root.allowsWrites {
                ContentUnavailableView(
                    "This Folder Is Empty",
                    systemImage: "folder",
                    description: Text("Drop files here or use Upload.")
                )
            } else {
                ContentUnavailableView("This Folder Is Empty", systemImage: "folder")
            }
        case _ where items.isEmpty && isFiltering:
            ContentUnavailableView.search(text: model.filterText)
        default:
            EmptyView()
        }
    }

    private var isFiltering: Bool {
        !model.filterText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
