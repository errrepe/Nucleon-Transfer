// Nucleon Transfer — Kind column value for drive rows (F8.4-U3).
// UTType's localized description per extension ("PDF document"), "Folder"
// for folders (ItemKindDescription holds the rules). Descriptions are
// cached per extension behind a Mutex: the Table sorts on this key path,
// and a sort compares far more often than there are distinct extensions.
import Synchronization
import UniformTypeIdentifiers

enum ItemKind {
    private static let cache = Mutex<[String: String]>([:])

    static func description(for item: DriveItem) -> String {
        ItemKindDescription.describe(isFolder: item.isFolder, fileExtension: item.fileExtension) { ext in
            if let hit = cache.withLock({ $0[ext] }) { return hit }
            let described = UTType(filenameExtension: ext)?.localizedDescription ?? ""
            cache.withLock { $0[ext] = described }
            return described
        }
    }
}

extension DriveItem {
    /// "Folder", "PDF document", "Document"… — the Kind column and its
    /// sort key.
    var kindDescription: String { ItemKind.description(for: self) }
}
