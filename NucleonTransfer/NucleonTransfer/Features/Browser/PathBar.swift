// Nucleon Transfer — optional Finder-style path bar (F8.4-U3).
// View ▸ Show Path Bar (⌥⌘P) shows it under each folder's table: one
// clickable segment per folder from the root down to that folder; a
// click pops the stack back to it.
import SwiftUI

struct PathBar: View {
    /// By parameter, like FolderView (R2/B1 — no environment reads).
    let model: BrowserModel
    /// The folder this bar describes — its own FolderView's, not
    /// `model.current`, so a view mid-push/pop never shows another path.
    let location: DriveLocation

    var body: some View {
        let chain = model.ancestors(of: location)
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
    return PathBar(model: model, location: model.current)
        .frame(width: 520)
        .preferredColorScheme(.light)
}

#Preview("Path Bar — Dark") {
    let model = BrowserModel.preview()
    return PathBar(model: model, location: model.current)
        .frame(width: 520)
        .preferredColorScheme(.dark)
}
#endif
