// Nucleon Transfer — browser view preferences (F8.4-U3/U4).
// @AppStorage / @SceneStorage keys shared by the browser views and the
// menu commands, plus the mapping between the persisted sort preference
// (Core BrowserSortPreference) and the Table's KeyPathComparators.
import Foundation

enum BrowserPreferences {
    /// View ▸ Show Path Bar (⌥⌘P) — off by default, like Finder.
    static let showPathBarKey = "browser.showPathBar"
    /// Sort column + direction, app-wide (@AppStorage, U4).
    static let sortOrderKey = "browser.sortOrder"
    /// Per-window state (@SceneStorage, U4).
    static let sidebarSelectionKey = "browser.sidebarSelection"
    static let lastFolderKey = "browser.lastFolder"
    static let columnCustomizationKey = "browser.columns"

    /// The saved sort order, or Name A→Z.
    static func savedSortOrder(_ defaults: UserDefaults = .standard) -> [KeyPathComparator<DriveItem>] {
        let raw = defaults.string(forKey: sortOrderKey) ?? ""
        return (BrowserSortPreference(rawValue: raw) ?? .default).comparators
    }
}

extension BrowserSortPreference {
    /// The Table comparator for this column — same comparators the
    /// FolderTable columns declare, so the header shows the indicator.
    var comparators: [KeyPathComparator<DriveItem>] {
        let order: SortOrder = ascending ? .forward : .reverse
        switch key {
        case .name: return [KeyPathComparator(\.name, comparator: .localizedStandard, order: order)]
        case .kind: return [KeyPathComparator(\.kindDescription, comparator: .localizedStandard, order: order)]
        case .modified: return [KeyPathComparator(\.modified, order: order)]
        case .size: return [KeyPathComparator(\.size, order: order)]
        }
    }

    /// The primary (first) comparator's column, nil for an unknown key path.
    init?(comparators: [KeyPathComparator<DriveItem>]) {
        guard let first = comparators.first else { return nil }
        let columns: [(PartialKeyPath<DriveItem>, Key)] = [
            (\DriveItem.name, .name),
            (\DriveItem.kindDescription, .kind),
            (\DriveItem.modified, .modified),
            (\DriveItem.size, .size),
        ]
        guard let key = columns.first(where: { $0.0 == first.keyPath })?.1 else { return nil }
        self.init(key: key, ascending: first.order == .forward)
    }
}
