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
        guard let max else { return "\(usedText) used" }
        return "\(usedText) of \(max.formatted(style)) used"
    }

    /// Status-bar row counts: "1 item" / "N items".
    static func itemCount(_ n: Int) -> String {
        n == 1 ? "1 item" : "\(n) items"
    }

    /// Window subtitle (F8.4-U3): "2 of 14 selected" while rows are
    /// selected, the plain item count otherwise.
    static func subtitle(selected: Int, total: Int) -> String {
        guard selected > 0 else { return itemCount(total) }
        return "\(min(selected, total)) of \(total) selected"
    }
}
