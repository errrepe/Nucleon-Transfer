// Nucleon Transfer — per-root browser container (F7 S2.2, R2 for B1).
// One NavigationStack per root: the path is BrowserModel.path
// (DriveLocation values). The toolbar filter field is declared by each
// FolderView (the topmost one owns the toolbar — a stack-level
// .searchable never showed).
// FolderView/FolderTable receive the model by PARAMETER — destination
// and toolbar content are hosted outside the normal subtree, where an
// environment object injected around the stack can be missing (crash
// B1). The .environment calls below stay as a safety net for any other
// child, and are also repeated on the stack root + inside the
// navigationDestination closure itself.
// MainView gives each root its own view identity with .id(root.id) and
// hands back the same cached BrowserModel when a root is revisited.
// F8.4-U3: the New Folder sheet, trash confirmationDialog and action
// alert are presented by ONE FolderView at a time — the topmost
// (`BrowserPresentations`, bound only where location == model.current).
// Attached outside the NavigationStack they never showed while a folder
// was pushed (the sheet appeared only after Back — live audit); the
// filter field's focus is published
// to the menu bar (⌘⌫ must stay delete-to-line-start while typing); the
// optional path bar lives in each FolderView (a stack-level inset was
// covered by every pushed folder — it showed on the root only).
// F8.4-U4: per-window state survives relaunch — the open folder chain
// (@SceneStorage, link IDs only, re-walked best-effort after the roots
// load) and the table's column widths/visibility/order; the sort order is
// app-wide (@AppStorage).
// F8.4-U7b: the trash confirmation carries a "Don't ask again" checkbox
// bound to the same setting as Settings › General "Ask before moving to
// Trash" (BrowserModel.requestTrash skips the dialog when it's off).
import SwiftUI

struct BrowserContainerView: View {
    @State private var model: BrowserModel
    /// The toolbar filter field has keyboard focus (F8.4-U3).
    @FocusState private var isSearchFocused: Bool
    /// Last sort column + direction (BrowserSortPreference raw value).
    @AppStorage(BrowserPreferences.sortOrderKey) private var savedSort = BrowserSortPreference.default.rawValue
    /// Share ID + folder link IDs of the open folder (FolderPathRestoration).
    @SceneStorage(BrowserPreferences.lastFolderKey) private var lastFolder = ""
    /// Column widths, visibility and order — shared by every FolderTable
    /// in the stack.
    @SceneStorage(BrowserPreferences.columnCustomizationKey)
    private var columnCustomization = TableColumnCustomization<DriveItem>()
    /// "Don't ask again" on the trash confirmation (AppSettings).
    @AppStorage(AppSettings.suppressTrashConfirmationKey)
    private var suppressTrashConfirmation = AppSettings.defaultSuppressTrashConfirmation

    /// A model kept alive across root switches (MainView's cache).
    init(model: BrowserModel) {
        _model = State(initialValue: model)
    }

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.path) {
            FolderView(location: model.rootLocation, model: model, columnCustomization: $columnCustomization,
                       isSearchFocused: $isSearchFocused)
                .modifier(BrowserPresentations(
                    model: model, isActive: model.current == model.rootLocation,
                    suppressTrashConfirmation: $suppressTrashConfirmation
                ))
                // Safety net on the stack root (R2/B1): any future child
                // that still reads the environment sees the objects.
                .environment(model)
                .environment(model.session)
                .navigationDestination(for: DriveLocation.self) { location in
                    FolderView(location: location, model: model, columnCustomization: $columnCustomization,
                           isSearchFocused: $isSearchFocused)
                        .modifier(BrowserPresentations(
                            model: model, isActive: model.current == location,
                            suppressTrashConfirmation: $suppressTrashConfirmation
                        ))
                        // Same net inside the destination closure — this
                        // content is hosted off-hierarchy by the stack.
                        .environment(model)
                        .environment(model.session)
                }
        }
        // S4.2: publish this browser to the menu bar (AppCommands), plus
        // the filter focus so Move to Trash yields ⌘⌫ to the text field.
        .focusedSceneValue(\.browserModel, model)
        .focusedSceneValue(\.browserSearchFocused, isSearchFocused)
        // Post-operation consistency (S2.3): create/trash/upload publish
        // the touched parents → token bumps → markStale + reload.
        .task(id: model.remoteChangedToken) {
            model.observeRemoteChanges()
        }
        // F8.4-U4: reopen the saved folder chain once, best-effort. A
        // path saved for another root is replaced by this root's (so
        // switching roots never jumps into an old deep folder later).
        .task {
            if let saved = FolderPathRestoration.decode(lastFolder),
               saved.shareID == model.root.shareID {
                await model.restorePath(linkIDs: saved.linkIDs)
            } else {
                lastFolder = FolderPathRestoration.encode(shareID: model.root.shareID, path: model.path)
            }
        }
        .onAppear {
            model.reappear(savedSortOrder: BrowserPreferences.savedSortOrder())
        }
        .onChange(of: model.path) { _, path in
            model.pathChangedOnScreen()
            lastFolder = FolderPathRestoration.encode(shareID: model.root.shareID, path: path)
        }
        .onChange(of: model.sortOrder) { _, order in
            if let preference = BrowserSortPreference(comparators: order) {
                savedSort = preference.rawValue
            }
        }
        .environment(model)
        // Children that need the session (S3.2 TransfersToolbarButton)
        // must see the SAME instance the model uses — including previews,
        // where no AppSession was injected higher up.
        .environment(model.session)
    }
}


/// The browser's modal presentations (F8.4-U3), attached to every
/// FolderView in the stack but live only on the topmost (`isActive`), so
/// exactly one presents and it does so from the visible folder.
private struct BrowserPresentations: ViewModifier {
    @Bindable var model: BrowserModel
    let isActive: Bool
    @Binding var suppressTrashConfirmation: Bool

    func body(content: Content) -> some View {
        content
            .sheet(isPresented: active($model.showingNewFolder)) {
                NewFolderSheet(
                    // R5: live duplicate check against the decrypted sibling
                    // names of the folder on screen — undecrypted items stay
                    // out and the server remains the safety net.
                    existingNames: Set(
                        model.state(for: model.current).items
                            .filter(\.isNameDecrypted).map(\.name)
                    )
                ) { name in
                    try await model.createFolder(named: name)
                }
            }
            // F8.2-R8: counts and trashes `pendingTrash` (the clicked rows or
            // the selection, whichever opened the dialog) — never the live
            // selection, which a context-menu click doesn't move.
            .confirmationDialog(
                "Move ^[\(model.pendingTrash.count) item](inflect: true) to Trash?",
                isPresented: active($model.confirmingTrash),
                titleVisibility: .visible
            ) {
                Button("Move to Trash", role: .destructive) {
                    model.confirmTrash()
                }
                Button("Cancel", role: .cancel) {
                    model.cancelTrash()
                }
            } message: {
                if model.pendingTrash.count == 1 {
                    Text("You can restore it from Trash in Proton Drive on the web.")
                } else {
                    Text("You can restore them from Trash in Proton Drive on the web.")
                }
            }
            .dialogSuppressionToggle(isSuppressed: $suppressTrashConfirmation)
            .alert(
                "Couldn’t Move to Trash",
                isPresented: Binding(
                    get: { isActive && model.actionError != nil },
                    set: { if !$0 { model.actionError = nil } }
                ),
                presenting: model.actionError
            ) { _ in
                Button("OK", role: .cancel) {}
            } message: { message in
                Text(message)
            }
    }

    /// `flag` on the topmost folder; a constant `false` everywhere else.
    private func active(_ flag: Binding<Bool>) -> Binding<Bool> {
        isActive ? flag : .constant(false)
    }
}

#if DEBUG
extension BrowserContainerView {
    /// Preview seam — injects a pre-seeded model (see `BrowserModel.preview`)
    /// so every browser state renders without network or a real session.
    init(preview model: BrowserModel) {
        _model = State(initialValue: model)
    }
}

#Preview("Folder — Light") {
    BrowserContainerView(preview: .preview())
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Folder — Dark") {
    BrowserContainerView(preview: .preview())
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}

#Preview("Empty — Light") {
    BrowserContainerView(preview: .preview(items: []))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Empty — Dark") {
    BrowserContainerView(preview: .preview(items: []))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}

#Preview("Error — Light") {
    BrowserContainerView(preview: .preview(
        items: [],
        error: "Network issue. Check your connection and try again."
    ))
    .frame(width: 720, height: 480)
    .preferredColorScheme(.light)
}

#Preview("Error — Dark") {
    BrowserContainerView(preview: .preview(
        items: [],
        error: "Network issue. Check your connection and try again."
    ))
    .frame(width: 720, height: 480)
    .preferredColorScheme(.dark)
}

#Preview("Loading — Light") {
    BrowserContainerView(preview: .preview(items: [], phase: .loading))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Loading — Dark") {
    BrowserContainerView(preview: .preview(items: [], phase: .loading))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}

// F8.4-U1: Proton refused an upload with code 2000 — banner + Upload
// controls disabled.
#Preview("Uploads Blocked — Light") {
    BrowserContainerView(preview: .preview(uploadsBlocked: true))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Uploads Blocked — Dark") {
    BrowserContainerView(preview: .preview(uploadsBlocked: true))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}

// F8.4-U3: a reload failed while earlier rows stay on screen.
#Preview("Refresh Failed — Light") {
    BrowserContainerView(preview: .preview(error: "Network issue."))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Refresh Failed — Dark") {
    BrowserContainerView(preview: .preview(error: "Network issue."))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}

#Preview("Photos — Read-Only") {
    BrowserContainerView(preview: .preview(root: PreviewFixtures.photosRoot))
        .frame(width: 720, height: 480)
}

// R6/B3: the Photos empty state — "No Photos" + read-only banner, no
// upload invitation.
#Preview("Photos Empty — Light") {
    BrowserContainerView(preview: .preview(root: PreviewFixtures.photosRoot, items: []))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.light)
}

#Preview("Photos Empty — Dark") {
    BrowserContainerView(preview: .preview(root: PreviewFixtures.photosRoot, items: []))
        .frame(width: 720, height: 480)
        .preferredColorScheme(.dark)
}
#endif
