// Nucleon Transfer — optional Finder-style path bar (F8.4-U3).
// View ▸ Show Path Bar (⌥⌘P) pins it to the bottom safe-area inset of the
// browser: one clickable segment per folder from the root down to the
// open folder; a click pops the stack back to that folder.
import SwiftUI

struct PathBar: View {
    /// By parameter, like FolderView (R2/B1 — no environment reads).
    let model: BrowserModel

    var body: some View {
        let chain = model.ancestors(of: model.current)
        ScrollView(.horizontal) {
            HStack(spacing: 2) {
                ForEach(Array(chain.enumerated()), id: \.offset) { index, location in
                    if index > 0 {
                        Image(systemName: "chevron.forward")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                            .accessibilityHidden(true)
                    }
                    Button {
                        model.pop(to: location)
                    } label: {
                        Label(location.name, systemImage: index == 0 ? rootSymbol : "folder")
                            .lineLimit(1)
                    }
                    .buttonStyle(.borderless)
                    .help(location.name)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 4)
        }
        .scrollIndicators(.never)
        .font(.caption)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Path")
    }

    /// Same symbols as the sidebar rows.
    private var rootSymbol: String {
        switch model.root.kind {
        case .photos: "photo.on.rectangle"
        case .device: "desktopcomputer"
        default: "folder"
        }
    }
}

#if DEBUG
#Preview("Path Bar — Light") {
    let model = BrowserModel.preview()
    model.path = [
        DriveLocation(shareID: "share-main", linkID: "link-documents", name: "Documents"),
        DriveLocation(shareID: "share-main", linkID: "link-invoices", name: "Invoices"),
    ]
    return PathBar(model: model)
        .frame(width: 520)
        .preferredColorScheme(.light)
}

#Preview("Path Bar — Dark") {
    PathBar(model: .preview())
        .frame(width: 520)
        .preferredColorScheme(.dark)
}
#endif
