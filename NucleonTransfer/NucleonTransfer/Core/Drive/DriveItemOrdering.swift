// Nucleon Transfer — sort and filter for drive listings.
// Sorting applies the caller's comparators, then a stable partition so
// folders always precede files. Filtering matches the display name.
// F8.3-P3: `visible` fuses filter + sort (partition first, then sort each
// group — fewer localized comparisons, no extra passes) and
// `VisibleItemsMemo` caches its result per folder so a SwiftUI body
// re-evaluation that changed nothing costs a key compare, not a re-sort.
import Foundation

enum DriveItemOrdering {
    /// Sorts by `comparators` (the Table column order), then partitions the
    /// result with folders first. The partition is stable: inside each group
    /// the comparator order is preserved. Empty comparators just group.
    static func sorted(
        _ items: [DriveItem],
        using comparators: [KeyPathComparator<DriveItem>]
    ) -> [DriveItem] {
        var folders: [DriveItem] = []
        var files: [DriveItem] = []
        folders.reserveCapacity(items.count)
        files.reserveCapacity(items.count)
        for item in items {
            if item.isFolder { folders.append(item) } else { files.append(item) }
        }
        // `sorted(using:)` is stable, so partition-then-sort orders exactly
        // like sort-then-stable-partition — with two smaller sorts.
        guard !comparators.isEmpty else { return folders + files }
        return folders.sorted(using: comparators) + files.sorted(using: comparators)
    }

    /// Name filter for the search field. Empty/whitespace queries return the
    /// input untouched; matching is case- and diacritic-insensitive
    /// (`localizedStandardContains`).
    static func filtered(_ items: [DriveItem], query: String) -> [DriveItem] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return items }
        return items.filter { $0.name.localizedStandardContains(trimmed) }
    }

    /// The rows a folder screen shows: `filtered` then `sorted`.
    static func visible(
        _ items: [DriveItem],
        query: String,
        using comparators: [KeyPathComparator<DriveItem>]
    ) -> [DriveItem] {
        sorted(filtered(items, query: query), using: comparators)
    }
}

/// One folder's cached `DriveItemOrdering.visible` result (F8.3-P3).
/// Recomputes only when the source version, the sort order or the
/// (trimmed) filter text differ from the last call. The owner bumps
/// `version` whenever it replaces or edits the source rows.
struct VisibleItemsMemo {
    private struct Key: Equatable {
        let version: UInt64
        let comparators: [KeyPathComparator<DriveItem>]
        let query: String
    }

    private var key: Key?
    private var cached: [DriveItem] = []
    /// How many times the rows were actually recomputed (tests/benchmarks).
    private(set) var computeCount = 0

    mutating func items(
        from source: [DriveItem],
        version: UInt64,
        query: String,
        using comparators: [KeyPathComparator<DriveItem>]
    ) -> [DriveItem] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        let next = Key(version: version, comparators: comparators, query: trimmed)
        if next == key { return cached }
        cached = DriveItemOrdering.visible(source, query: trimmed, using: comparators)
        key = next
        computeCount += 1
        return cached
    }
}
