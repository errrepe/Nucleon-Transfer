// Nucleon Transfer — reopen the last folder after relaunch (F8.4-U4).
// The browser saves its NavigationStack path to @SceneStorage as share ID
// + folder link IDs only — opaque server identifiers, never decrypted
// names. On launch the chain is re-walked from the root: each link ID must
// still be a folder inside the previous one (names come fresh from the
// listing). The walk stops at the first missing/moved folder, so a stale
// path degrades to its longest valid prefix instead of an error screen.
import Foundation

enum FolderPathRestoration {
    struct Saved: Codable, Equatable, Sendable {
        let shareID: String
        let linkIDs: [String]
    }

    /// Deeper paths are cut — a restore never walks an unbounded chain.
    static let maxDepth = 64

    static func encode(shareID: String, path: [DriveLocation]) -> String {
        let saved = Saved(shareID: shareID, linkIDs: path.prefix(maxDepth).map(\.linkID))
        guard let data = try? JSONEncoder().encode(saved) else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    /// nil for empty/garbled storage.
    static func decode(_ raw: String) -> Saved? {
        guard !raw.isEmpty,
              let saved = try? JSONDecoder().decode(Saved.self, from: Data(raw.utf8))
        else { return nil }
        return Saved(shareID: saved.shareID, linkIDs: Array(saved.linkIDs.prefix(maxDepth)))
    }

    /// Re-walks `linkIDs` from `root`. `children` lists a folder (nil =
    /// couldn't list); runs on the caller's actor, so it may read
    /// main-actor caches. Returns the valid prefix with current names.
    static func resolve(
        linkIDs: [String],
        root: DriveLocation,
        isolation: isolated (any Actor)? = #isolation,
        children: (DriveLocation) async -> [DriveItem]?
    ) async -> [DriveLocation] {
        var path: [DriveLocation] = []
        var parent = root
        for linkID in linkIDs.prefix(maxDepth) {
            guard let items = await children(parent),
                  let folder = items.first(where: { $0.id == linkID && $0.isFolder })
            else { break }
            let location = folder.location
            path.append(location)
            parent = location
        }
        return path
    }
}
