// Nucleon Transfer — signed-in shell (F7 S2.1 + S2.2).
// NavigationSplitView: classified roots in the sidebar, BrowserContainerView
// (Table + folder navigation) in the detail column. While roots load, a
// spinner; on failure, a retryable unavailable view.
// S3.2: transfers UI moved to the FolderView toolbar popover
// (TransfersToolbarButton) — the queue sheet is gone.
// F8.4-U4: the sidebar selection lives in @SceneStorage (SidebarItem's
// string form), read directly by the binding so the first frame already
// shows the restored root; a vanished share falls back to the first root.
import SwiftUI

struct MainView: View {
    @Environment(AppSession.self) private var session
    /// SidebarItem.storageValue; "" = nothing selected.
    @SceneStorage(BrowserPreferences.sidebarSelectionKey)
    private var storedSelection = SidebarItem.myFiles.storageValue

    private var selection: Binding<SidebarItem?> {
        Binding(
            // Unreadable (older/garbled) values fall back to My Files.
            get: { storedSelection.isEmpty ? nil : SidebarItem(storageValue: storedSelection) ?? .myFiles },
            set: { storedSelection = $0?.storageValue ?? "" }
        )
    }

    var body: some View {
        Group {
            if let roots = session.roots {
                splitView(roots: roots)
            } else if let error = session.rootsError {
                ContentUnavailableView {
                    Label("Couldn't Load Your Drive", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error)
                } actions: {
                    Button("Try Again") { Task { await session.loadRoots() } }
                }
            } else {
                ProgressView("Loading your drive…")
            }
        }
        .frame(minWidth: 800, minHeight: 500)
    }

    private func splitView(roots: DriveRoots) -> some View {
        NavigationSplitView {
            SidebarView(selection: selection)
                .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
        } detail: {
            if let root = selectedRoot(in: roots) {
                // One browser stack per root — .id rebuilds the model, path
                // and caches when the sidebar selection changes.
                BrowserContainerView(root: root, session: session)
                    .id(root.id)
            } else if roots.all.isEmpty {
                ContentUnavailableView(
                    "No Drive Locations",
                    systemImage: "externaldrive",
                    description: Text("This account has no browsable drives.")
                )
            } else {
                ContentUnavailableView(
                    "Select a Location",
                    systemImage: "sidebar.left"
                )
            }
        }
    }

    /// The root for the sidebar selection, or nil when nothing is selected
    /// (detail shows "Select a Location"). A selection whose share vanished
    /// after a reload falls back to the first root so the detail never
    /// strands.
    private func selectedRoot(in roots: DriveRoots) -> DriveRoot? {
        guard let item = selection.wrappedValue else { return nil }
        return item.root(in: roots) ?? roots.all.first
    }
}

#if DEBUG
#Preview("Light") {
    MainView()
        .environment(PreviewFixtures.session())
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    MainView()
        .environment(PreviewFixtures.session())
        .preferredColorScheme(.dark)
}

#Preview("Roots Error") {
    MainView()
        .environment(PreviewFixtures.session(
            roots: nil,
            rootsError: "Network issue. Check your connection."
        ))
}
#endif
