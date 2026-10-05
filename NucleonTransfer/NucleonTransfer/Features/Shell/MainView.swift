// Nucleon Transfer — signed-in shell (F7 S2.1 + S2.2).
// NavigationSplitView: classified roots in the sidebar, BrowserContainerView
// (Table + folder navigation) in the detail column. While roots load, a
// spinner; on failure, a retryable unavailable view.
// S3.2: transfers UI moved to the FolderView toolbar popover
// (TransfersToolbarButton) — the queue sheet is gone.
// F8.4-U4: the sidebar selection lives in @SceneStorage (SidebarItem's
// string form), read directly by the binding so the first frame already
// shows the restored root; a vanished share falls back to the first root.
// Polish pass: loading → split view / error crossfades.
// Each root's BrowserModel is cached for the life of the shell, so a
// sidebar switch back to a root lands on its folder and rows without a
// spinner (live audit); sign-out unmounts MainView and drops the cache.
// Polish pass 3: "Try Again" on the roots error shows a spinner while it
// runs, and a repeat failure wiggles the warning symbol — the message is
// usually identical, so without it nothing on screen would change.
import SwiftUI

struct MainView: View {
    @Environment(AppSession.self) private var session
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var browsers = BrowserCache()
    /// "Try Again" on the roots error is in flight.
    @State private var isRetryingRoots = false
    /// Failed retries — wiggles the error symbol on each one.
    @State private var rootsRetryFailures = 0
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
                    Label {
                        Text("Couldn't Load Your Drive")
                    } icon: {
                        Image(systemName: "exclamationmark.triangle")
                            // Movement-free pulse under Reduce Motion.
                            .symbolEffect(.wiggle, value: reduceMotion ? 0 : rootsRetryFailures)
                            .symbolEffect(.pulse, value: reduceMotion ? rootsRetryFailures : 0)
                    }
                } description: {
                    Text(error)
                } actions: {
                    Button(action: retryRoots) {
                        // ZStack: the two labels overlap mid-crossfade.
                        ZStack {
                            if isRetryingRoots {
                                ProgressView()
                                    .controlSize(.small)
                                    .transition(.opacity)
                            } else {
                                Text("Try Again")
                                    .transition(.opacity)
                            }
                        }
                        // Fixed width so the button doesn't jump.
                        .frame(minWidth: 70)
                    }
                    .disabled(isRetryingRoots)
                    .accessibilityLabel(isRetryingRoots ? Text("Loading your drive…") : Text("Try Again"))
                }
                .animation(Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion), value: isRetryingRoots)
                .transition(.opacity)
            } else {
                DelayedProgressView(title: "Loading your drive…")
                    .transition(.opacity)
            }
        }
        .animation(Motion.adaptive(Motion.smooth, reduceMotion: reduceMotion), value: rootsState)
        .frame(minWidth: 800, minHeight: 500)
    }

    private func splitView(roots: DriveRoots) -> some View {
        NavigationSplitView {
            SidebarView(selection: selection)
                .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
        } detail: {
            if let root = selectedRoot(in: roots) {
                // One browser stack per root — .id rebuilds the stack's view
                // state on a sidebar switch; the model (path + caches) comes
                // back from BrowserCache.
                BrowserContainerView(model: browsers.model(for: root, session: session))
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

    /// "Try Again": reload the roots; a repeat failure bumps the wiggle.
    private func retryRoots() {
        guard !isRetryingRoots else { return }
        isRetryingRoots = true
        Task {
            await session.loadRoots()
            isRetryingRoots = false
            if session.rootsError != nil { rootsRetryFailures += 1 }
        }
    }

    /// 0 loading, 1 loaded, 2 failed — what the crossfade keys on.
    private var rootsState: Int {
        if session.roots != nil { return 1 }
        return session.rootsError == nil ? 0 : 2
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

/// One BrowserModel per drive root, created on first visit. A plain
/// reference (not observed): filling it during a body pass invalidates
/// nothing.
@MainActor
private final class BrowserCache {
    private var models: [String: BrowserModel] = [:]

    func model(for root: DriveRoot, session: AppSession) -> BrowserModel {
        if let model = models[root.id] { return model }
        let model = BrowserModel(
            root: root, session: session,
            sortOrder: BrowserPreferences.savedSortOrder()
        )
        models[root.id] = model
        return model
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
