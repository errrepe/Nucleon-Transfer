// Nucleon Transfer — ordering guard for folder listings (F8.2-R7).
// BrowserModel can have several listings of the same folder in flight (a
// markStale reload during a slow load, a user reload, a post-trash
// refresh). Without a guard they finish in any order and the OLDER
// listing can win, and a listing requested before an optimistic trash
// can resurrect the rows the trash just removed. The gate hands out one
// monotonically increasing token per request — only the folder's latest
// token may apply its result — and filters optimistic removals out of
// every listing that was requested before the removal was known to have
// landed server-side. Pure value type: no I/O, MainActor-agnostic.
import Foundation

struct FolderLoadGate: Sendable {
    /// One optimistic removal (trash) in a folder.
    private struct Removal: Sendable {
        let handle: UInt64
        let ids: Set<DriveItem.ID>
        /// nil while the server call runs; once it succeeded, the last
        /// token issued at that moment — listings with a token up to the
        /// fence were requested before the removal landed and may still
        /// contain the rows.
        var fence: UInt64?
    }

    private var counter: UInt64 = 0
    /// Folder linkID → token of the latest listing request.
    private var latest: [String: UInt64] = [:]
    private var removals: [String: [Removal]] = [:]

    /// Registers a new listing request for `folder`; any earlier request
    /// for the same folder is superseded.
    mutating func begin(folder: String) -> UInt64 {
        counter &+= 1
        latest[folder] = counter
        return counter
    }

    /// True while `token` is the latest request for `folder`.
    func isCurrent(_ token: UInt64, folder: String) -> Bool {
        latest[folder] == token
    }

    /// The result of request `token`: nil when a newer request for the
    /// folder superseded it (drop it), else `items` minus every
    /// optimistic removal the listing may predate. A listing newer than a
    /// landed removal's fence retires that removal.
    mutating func apply(_ items: [DriveItem], token: UInt64, folder: String) -> [DriveItem]? {
        guard isCurrent(token, folder: folder) else { return nil }
        guard var pending = removals[folder], !pending.isEmpty else { return items }
        var hidden = Set<DriveItem.ID>()
        for removal in pending where removal.fence.map({ token <= $0 }) ?? true {
            hidden.formUnion(removal.ids)
        }
        pending.removeAll { removal in removal.fence.map { token > $0 } ?? false }
        removals[folder] = pending.isEmpty ? nil : pending
        return hidden.isEmpty ? items : items.filter { !hidden.contains($0.id) }
    }

    /// Records an optimistic removal of `ids` from `folder` (call before
    /// the server request). Returns the handle for `finishRemoval`.
    mutating func beginRemoval(_ ids: Set<DriveItem.ID>, folder: String) -> UInt64 {
        counter &+= 1
        removals[folder, default: []].append(Removal(handle: counter, ids: ids, fence: nil))
        return counter
    }

    /// Ends a removal. Success fences it at the current token, so only
    /// listings requested from now on show the server's truth unfiltered;
    /// failure drops it (the rows really are still there).
    mutating func finishRemoval(_ handle: UInt64, folder: String, succeeded: Bool) {
        guard var pending = removals[folder],
              let index = pending.firstIndex(where: { $0.handle == handle })
        else { return }
        if succeeded {
            pending[index].fence = counter
        } else {
            pending.remove(at: index)
        }
        removals[folder] = pending.isEmpty ? nil : pending
    }
}
