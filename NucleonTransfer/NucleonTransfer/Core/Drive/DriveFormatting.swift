// Nucleon Transfer — display strings for sizes, quota and item counts.
// Byte strings come from ByteCountFormatStyle (.file style, decimal units)
// so listings read like Finder.
import Foundation

enum DriveFormatting {
    /// "—" for folders (their wire size is ciphertext size — B2), otherwise
    /// the file size formatted in the given locale.
    static func size(_ item: DriveItem, locale: Locale = .current) -> String {
        guard !item.isFolder else { return "—" }
        return item.size.formatted(ByteCountFormatStyle(style: .file).locale(locale))
    }

    /// "148.48 GB of 520 GB used" with a quota, "148.48 GB used" without.
    static func storage(used: Int64, max: Int64?, locale: Locale = .current) -> String {
        let style = ByteCountFormatStyle(style: .file).locale(locale)
        let usedText = used.formatted(style)
        guard let max else { return String(localized: "\(usedText) used", comment: "Storage footer without a quota") }
        let maxText = max.formatted(style)
        return String(localized: "\(usedText) of \(maxText) used", comment: "Storage footer: used of quota")
    }

    /// Status-bar row counts: "1 item" / "N items". Plural via inflection
    /// (catalog plural variants in the app, English inflection where no
    /// catalog is bundled — swift test).
    static func itemCount(_ n: Int) -> String {
        String(AttributedString(localized: "^[\(n) item](inflect: true)", comment: "Item count").characters)
    }

    /// Window subtitle (F8.4-U3): "2 of 14 selected" while rows are
    /// selected, the plain item count otherwise.
    static func subtitle(selected: Int, total: Int) -> String {
        guard selected > 0 else { return itemCount(total) }
        let shown = min(selected, total)
        return String(localized: "\(shown) of \(total) selected", comment: "Window subtitle: selected rows of all rows")
    }
}
