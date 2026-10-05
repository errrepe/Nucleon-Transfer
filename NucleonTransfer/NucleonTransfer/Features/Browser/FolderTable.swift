// Nucleon Transfer — the drive listing as a sortable table (F7 S2.2/S2.3).
// Columns per spec 6.3: Name (16×16 system icon + middle-truncated name +
// lock badge for undecrypted names, warning badge for unverified
// signatures — F8.1-S2), Modified (monospaced digits), Size
// (folders show "—", trailing-aligned). Selection and sort order live in
// BrowserModel; DriveItemOrdering keeps folders first under any order.
// S2.3 context menus (spec 6.3): Open / Download… / Move to Trash on a
// selection; S3.1 fills the empty-area menu with New Folder / Upload
// Files… / Upload Folder… / Reload.
// B10: the Table uses the explicit columns/rows init so each folder row
// is its own drop target (TableRow.dropDestination — the only per-row
// drop API; the system draws the row highlight). File rows carry no
// modifier, so a drop on them falls through to the table-level .onDrop
// in FolderView targeting the open folder.
// F8.3-P3: the row under the pointer lives in a tiny @Observable
// (`RowHoverState`) instead of FolderView @State — pointer moves no longer
// re-evaluate FolderView/FolderTable, only the drop overlay that reads it.
// F8.4-U3: a Kind column (UTType description, "Folder" for folders) and
// Finder-style Modified dates ("Today at 14:32", "Yesterday at …").
import SwiftUI

/// The row under the pointer, written by FolderTable's row hover handlers
/// and read only by the drop overlay (B10 destination label). Kept out of
/// any view's body so hovering doesn't invalidate the folder screen.
@MainActor
@Observable
final class RowHoverState {
    private(set) var item: DriveItem?

    /// Leaving a row only clears the state when it still names that row;
    /// unchanged values are not re-assigned (no spurious notifications).
    func track(_ row: DriveItem, hovering: Bool) {
        if hovering {
            if item != row { item = row }
        } else if item == row {
            item = nil
        }
    }
}

struct FolderTable: View {
    /// The visible rows for the current folder — already filtered and
    /// sorted by BrowserModel.visibleItems(for:).
    let items: [DriveItem]

    /// Passed in by FolderView — never read from the environment. A table
    /// inside a pushed navigationDestination cannot count on an object
    /// injected outside the NavigationStack (crash B1). @Bindable keeps
    /// the $model.selection / $model.sortOrder Table bindings.
    @Bindable var model: BrowserModel

    /// The row under the pointer — FolderView's drop overlay resolves it
    /// through DropTargeting so it names the real destination. Written
    /// from hover callbacks only, never read in `body`.
    let hover: RowHoverState

    var body: some View {
        Table(of: DriveItem.self, selection: $model.selection, sortOrder: $model.sortOrder) {
            TableColumn("Name", value: \.name, comparator: .localizedStandard) { item in
                HStack(spacing: 6) {
                    FileIcon(item: item)
                    Text(item.name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if !item.isNameDecrypted {
                        Image(systemName: "lock.trianglebadge.exclamationmark")
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Name couldn't be decrypted")
                            .help("This name couldn't be decrypted with your current keys.")
                    }
                    if item.signatureIssue {
                        // F8.1-S2: content-level signature failure — the
                        // row stays usable; the badge warns (official
                        // clients' "signature could not be verified").
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundStyle(.yellow)
                            .help("The signature of this item could not be verified.")
                    }
                }
                // A2: VoiceOver reads the cell as ONE element —
                // "Invoice March.pdf, file" — instead of icon/text/badge
                // fragments; the explicit label wins over the combined
                // children so the caveat suffix reads once.
                .accessibilityElement(children: .combine)
                .accessibilityLabel(Self.nameAccessibilityLabel(for: item))
            }
            .width(min: 160, ideal: 280)
            TableColumn("Kind", value: \.kindDescription, comparator: .localizedStandard) { item in
                Text(item.kindDescription)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .width(min: 80, ideal: 120)
            TableColumn("Modified", value: \.modified) { item in
                Text(ModifiedDateFormatting.string(for: item.modified))
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .lineLimit(1)
            }
            TableColumn("Size", value: \.size) { item in
                Text(DriveFormatting.size(item))
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            .alignment(.trailing)
        } rows: {
            ForEach(items) { item in
                if item.isFolder && model.canUpload {
                    TableRow(item)
                        .onHover { hover.track(item, hovering: $0) }
                        // B10: a drop on this row uploads into THAT
                        // folder — pinned by location, so a mid-drop
                        // navigation can't retarget it.
                        .dropDestination(for: URL.self) { urls in
                            Task { await model.upload(urls: urls, to: item.location) }
                        }
                } else {
                    TableRow(item)
                        .onHover { hover.track(item, hovering: $0) }
                }
            }
        }
        // M3: with zero rows the zebra stripes still draw behind the
        // ContentUnavailableView overlay — disable alternation so the
        // empty state reads clean. The Table itself stays put: it owns
        // the drop target and the empty-area context menu.
        .alternatingRowBackgrounds(items.isEmpty ? .disabled : .enabled)
        .contextMenu(forSelectionType: DriveItem.ID.self) { ids in
            // Spec-6.3: an empty ids set is a right-click on the table's
            // empty area — show the folder-level menu (New Folder, the
            // S3.1 upload pair, Reload). Selection menu: Open (folders
            // only), Download…, divider, Move to Trash.
            if ids.isEmpty {
                Button("New Folder") { model.showingNewFolder = true }
                    .disabled(!model.root.allowsWrites)
                // F8.4-U1: also off while Proton blocks uploads (2000).
                Button("Upload Files…") { Task { await model.uploadPanel(folders: false) } }
                    .disabled(!model.canUpload)
                Button("Upload Folder…") { Task { await model.uploadPanel(folders: true) } }
                    .disabled(!model.canUpload)
                Divider()
                Button("Reload") { Task { await model.reloadCurrent() } }
            } else {
                if items.contains(where: { ids.contains($0.id) && $0.isFolder }) {
                    Button("Open") { model.openSelection(ids) }
                }
                Button("Download…") { model.downloadItems(ids) }
                Divider()
                // F8.2-R8: the clicked rows, never `model.selection` — a
                // right-click on an unselected row leaves the selection
                // where it was.
                Button("Move to Trash") { model.requestTrash(ids) }
                    .disabled(!model.root.allowsWrites)
            }
        } primaryAction: { ids in
            model.openSelection(ids)
        }
    }

    /// A2: one VoiceOver phrase for the Name cell — "Invoices, folder",
    /// "report.pdf, file" — plus the decryption caveat when the lock
    /// badge shows (the visible name is the "Encrypted Item" placeholder).
    private static func nameAccessibilityLabel(for item: DriveItem) -> String {
        var label = "\(item.name), \(item.isFolder ? "folder" : "file")"
        if !item.isNameDecrypted { label += ", name couldn't be decrypted" }
        if item.signatureIssue { label += ", signature could not be verified" }
        return label
    }
}
