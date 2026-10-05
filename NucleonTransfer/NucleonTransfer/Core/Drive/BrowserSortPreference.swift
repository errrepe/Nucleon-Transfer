// Nucleon Transfer — persisted table sort order (F8.4-U4).
// The browser's sort is saved to @AppStorage as column key + direction
// ("modified:desc"); the app maps it to/from the Table's
// KeyPathComparators (the Kind key path lives app-side — UTType).
import Foundation

struct BrowserSortPreference: Equatable, Sendable, RawRepresentable {
    enum Key: String, CaseIterable, Sendable {
        case name, kind, modified, size
    }

    var key: Key
    var ascending: Bool

    /// Name, A→Z — the browser's default order.
    static let `default` = BrowserSortPreference(key: .name, ascending: true)

    init(key: Key, ascending: Bool) {
        self.key = key
        self.ascending = ascending
    }

    init?(rawValue: String) {
        let parts = rawValue.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, let key = Key(rawValue: String(parts[0])) else { return nil }
        switch parts[1] {
        case "asc": self.init(key: key, ascending: true)
        case "desc": self.init(key: key, ascending: false)
        default: return nil
        }
    }

    var rawValue: String { "\(key.rawValue):\(ascending ? "asc" : "desc")" }
}
