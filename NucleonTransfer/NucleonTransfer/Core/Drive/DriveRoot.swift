// Nucleon Transfer — browsable drive roots (My Files / Photos / Computers).
// ShareCatalog collapses the raw ShareMetadata list into the roots the
// sidebar shows; pure model, no I/O.
import Foundation

/// One browsable drive root: a share plus the link its tree hangs from.
struct DriveRoot: Hashable, Sendable, Identifiable {
    var id: String { shareID }
    let shareID: String
    /// `ShareMetadata.linkID` — the root folder link of this share.
    let rootLinkID: String
    let volumeID: String
    let kind: ShareKind
    let displayName: String
    /// Only main and device ("Computer") shares accept writes here; photos
    /// go through their own API and standard/unknown shares are read-only.
    var allowsWrites: Bool { kind == .main || kind == .device }
}

/// The full set of drive roots, grouped by kind for the sidebar.
struct DriveRoots: Equatable, Sendable {
    var myFiles: DriveRoot?
    var photos: DriveRoot?
    var computers: [DriveRoot]
    /// `myFiles`, then `photos`, then `computers`, in that order.
    var all: [DriveRoot]

    init(myFiles: DriveRoot?, photos: DriveRoot?, computers: [DriveRoot]) {
        self.myFiles = myFiles
        self.photos = photos
        self.computers = computers
        var combined: [DriveRoot] = []
        if let myFiles { combined.append(myFiles) }
        if let photos { combined.append(photos) }
        combined.append(contentsOf: computers)
        all = combined
    }
}

/// Pure mapping from `ShareMetadata` wire rows to `DriveRoots`.
enum ShareCatalog {
    /// Builds the root catalog, dropping shares that are not browsable:
    /// `state != active`, `locked == true` or `volumeSoftDeleted == true`.
    /// `mainShareIDs` is the set of `Volume.share.shareID` values, used to
    /// pick the canonical main share when several `.main` rows exist.
    static func roots(from metas: [ShareMetadata], mainShareIDs: Set<String>) -> DriveRoots {
        let eligible = metas.filter {
            $0.state == ShareState.active && $0.locked != true && $0.volumeSoftDeleted != true
        }

        // Deterministic ordering: creationTime, then shareID as tiebreaker.
        let byAge = { (a: ShareMetadata, b: ShareMetadata) in
            (a.creationTime, a.shareID) < (b.creationTime, b.shareID)
        }

        // Canonical main share: prefer one referenced by a volume; among
        // candidates (or when none is referenced) take the oldest.
        let mains = eligible.filter { ShareKind(rawType: $0.type) == .main }
        let myFilesMeta = mains.filter { mainShareIDs.contains($0.shareID) }.min(by: byAge)
            ?? mains.min(by: byAge)
        let myFiles = myFilesMeta.map { root(from: $0, kind: .main, name: String(localized: "My Files", comment: "Sidebar: the user’s main Proton Drive volume")) }

        let photos = eligible
            .first { ShareKind(rawType: $0.type) == .photos }
            .map { root(from: $0, kind: .photos, name: String(localized: "Photos", comment: "Sidebar: the Proton Drive Photos volume")) }

        let computers = eligible
            .filter { ShareKind(rawType: $0.type) == .device }
            .sorted(by: byAge)
            .enumerated()
            .map { index, meta in root(from: meta, kind: .device, name: String(localized: "Computer \(index + 1)", comment: "Sidebar: a computer backup share, numbered")) }

        return DriveRoots(myFiles: myFiles, photos: photos, computers: computers)
    }

    private static func root(from meta: ShareMetadata, kind: ShareKind, name: String) -> DriveRoot {
        DriveRoot(
            shareID: meta.shareID, rootLinkID: meta.linkID,
            volumeID: meta.volumeID, kind: kind, displayName: name
        )
    }
}
