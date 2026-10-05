// Nucleon Transfer — the browser's "Kind" column text (F8.4-U3).
// Folders read "Folder"; files use the system description of their
// extension (UTType.localizedDescription, injected by the app so Core
// stays Foundation-only), falling back to "Document" like Finder does for
// types it doesn't know.
import Foundation

enum ItemKindDescription {
    static func describe(
        isFolder: Bool,
        fileExtension: String,
        lookup: (String) -> String?
    ) -> String {
        if isFolder { return String(localized: "Folder") }
        let ext = fileExtension.lowercased()
        if !ext.isEmpty, let described = lookup(ext), !described.isEmpty {
            return described
        }
        return String(localized: "Document")
    }
}
