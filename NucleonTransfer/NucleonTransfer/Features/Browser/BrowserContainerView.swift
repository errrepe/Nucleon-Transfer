// Nucleon Transfer — per-root browser container (F7 S2.2, R2 for B1).
// One NavigationStack per root: the path is BrowserModel.path
// (DriveLocation values) and the filter field lives in the toolbar.
// FolderView/FolderTable receive the model by PARAMETER — destination
// and toolbar content are hosted outside the normal subtree, where an
// environment object injected around the stack can be missing (crash
// B1). The .environment calls below stay as a safety net for any other
// child, and are also repeated on the stack root + inside the
// navigationDestination closure itself.
// MainView gives each root its own instance with .id(root.id).
import SwiftUI

struct BrowserContainerView: View {
    @State private var model: BrowserModel

    init(root: DriveRoot, session: AppSession) {
        _model = State(initialValue: BrowserModel(root: root, session: session))
    }

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.path) {
            FolderView(location: model.rootLocation, model: model)
                // Safety net on the stack root (R2/B1): any future child
                // that still reads the environment sees the objects.
                .environment(model)
                .environment(model.session)
                .navigationDestination(for: DriveLocation.self) { location in
                    FolderView(location: location, model: model)
                        // Same net inside the destination closure — this
                        // content is hosted off-hierarchy by the stack.
                        .environment(model)
                        .environment(model.session)
                }
        }
        .searchable(
            text: $model.filterText,
            placement: .toolbar,
            prompt: "Filter this folder"
        )
        // Post-operation consistency (S2.3): create/trash/upload publish
        // the touched parents → token bumps → markStale + reload.
        .task(id: model.remoteChangedToken) {
            model.observeRemoteChanges()
        }
        .environment(model)
        // Children that need the session (S3.2 TransfersToolbarButton)
        // must see the SAME instance the model uses — including previews,
        // where no AppSession was injected higher up.
        .environment(model.session)
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
