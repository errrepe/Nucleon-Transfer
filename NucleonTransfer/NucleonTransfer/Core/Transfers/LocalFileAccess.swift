// Nucleon Transfer — sandboxed access to an upload job's local file (F8.2-R4).
// After a relaunch the drop's security scope is gone: the job's bookmark
// must be resolved AND `startAccessingSecurityScopedResource()` called on
// the resolved URL, or every read fails ("local file missing"). Access is
// held for the job only and stopped exactly once (success, failure or
// cancellation). A stale bookmark is re-created from the resolved URL so
// the next relaunch still resolves. Filesystem/bookmark calls go through
// closures so the decision logic is testable without real grants.

import Foundation

/// Injectable bookmark + scope primitives (`.live` in the app).
struct LocalFileAccess: Sendable {
    var fileExists: @Sendable (_ path: String) -> Bool
    var resolveBookmark: @Sendable (_ bookmark: Data) throws -> (url: URL, isStale: Bool)
    var makeBookmark: @Sendable (_ url: URL) throws -> Data
    var startAccessing: @Sendable (_ url: URL) -> Bool
    var stopAccessing: @Sendable (_ url: URL) -> Void

    static let live = LocalFileAccess(
        fileExists: { FileManager.default.fileExists(atPath: $0) },
        resolveBookmark: { data in
            var stale = false
            let url = try URL(
                resolvingBookmarkData: data,
                options: .withSecurityScope,
                relativeTo: nil,
                bookmarkDataIsStale: &stale
            )
            return (url, stale)
        },
        makeBookmark: { url in
            try url.bookmarkData(
                options: .withSecurityScope,
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
        },
        startAccessing: { $0.startAccessingSecurityScopedResource() },
        stopAccessing: { $0.stopAccessingSecurityScopedResource() }
    )

    /// An opened job file. `close` it exactly once (use `defer`).
    struct Opened: Sendable {
        let url: URL
        /// True when `startAccessing` succeeded and must be balanced.
        let scoped: Bool
        /// Fresh bookmark when the stored one was stale (persist it).
        let refreshedBookmark: Data?
    }

    /// Bookmark first (it carries the sandbox grant and survives moves),
    /// then the enqueue-time path (same session, grant still held by the
    /// coordinator, or an unsandboxed test run).
    func open(_ job: TransferJob) throws -> Opened {
        if let bookmark = job.localBookmark,
           let resolved = try? resolveBookmark(bookmark)
        {
            let scoped = startAccessing(resolved.url)
            if fileExists(resolved.url.path) {
                let refreshed = resolved.isStale ? (try? makeBookmark(resolved.url)) : nil
                return Opened(url: resolved.url, scoped: scoped, refreshedBookmark: refreshed)
            }
            if scoped { stopAccessing(resolved.url) }
        }
        if fileExists(job.localPath) {
            return Opened(url: URL(fileURLWithPath: job.localPath), scoped: false, refreshedBookmark: nil)
        }
        throw TransferFailure.permanent("local file missing — re-add \(job.fileName)")
    }

    func close(_ opened: Opened) {
        if opened.scoped { stopAccessing(opened.url) }
    }
}

/// Which drop-level security grants can be released (F8.2-R4): a grant
/// opened for a drop is held while any of its jobs may still read through
/// it, and released once every one of them is finished (done / failed /
/// cancelled) or removed. Paused/queued/uploading jobs keep it.
struct UploadGrantLedger<Key: Hashable & Sendable>: Sendable {
    private var held: [Key: Set<UUID>] = [:]

    var isEmpty: Bool { held.isEmpty }
    var keys: [Key] { Array(held.keys) }

    mutating func hold(_ key: Key, for jobIDs: [UUID]) {
        held[key, default: []].formUnion(jobIDs)
    }

    /// Keys whose jobs are all finished in `snapshot`; removed from the ledger.
    mutating func releasable(in snapshot: [TransferJob]) -> [Key] {
        let live = Set(snapshot.lazy
            .filter { $0.state == .queued || $0.state == .uploading || $0.state == .paused }
            .map(\.id))
        var out: [Key] = []
        for (key, ids) in held where ids.isDisjoint(with: live) {
            out.append(key)
        }
        for key in out { held[key] = nil }
        return out
    }

    /// Everything (sign-out).
    mutating func releaseAll() -> [Key] {
        defer { held.removeAll() }
        return Array(held.keys)
    }
}
