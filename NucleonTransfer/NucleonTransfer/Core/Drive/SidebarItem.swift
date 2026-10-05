// Nucleon Transfer — sidebar selection model (F7 S2.1).
// Value identity for the sidebar rows; resolves to a `DriveRoot` against the
// loaded `DriveRoots` so selection survives reloads by shareID, not index.
// F8.4-U4: a stable string form for @SceneStorage (moved to Core so the
// round-trip is unit-tested): "myFiles", "photos", "computer:<shareID>".
import Foundation

enum SidebarItem: Hashable {
    case myFiles
    case photos
    case computer(shareID: String)

    /// The root this selection points at, or nil when that share is absent
    /// from the loaded catalog (e.g. a removed device share).
    func root(in roots: DriveRoots) -> DriveRoot? {
        switch self {
        case .myFiles:
            return roots.myFiles
        case .photos:
            return roots.photos
        case .computer(let shareID):
            return roots.computers.first { $0.shareID == shareID }
        }
    }
}

extension SidebarItem {
    /// Persisted form for scene restoration. A share ID is an opaque
    /// server identifier — no user data.
    var storageValue: String {
        switch self {
        case .myFiles: "myFiles"
        case .photos: "photos"
        case .computer(let shareID): "computer:" + shareID
        }
    }

    /// Parses `storageValue`; anything else (empty, older/unknown form)
    /// is nil — the caller picks its default.
    init?(storageValue: String) {
        switch storageValue {
        case "myFiles": self = .myFiles
        case "photos": self = .photos
        default:
            let prefix = "computer:"
            guard storageValue.hasPrefix(prefix) else { return nil }
            let shareID = String(storageValue.dropFirst(prefix.count))
            guard !shareID.isEmpty else { return nil }
            self = .computer(shareID: shareID)
        }
    }
}
