// Nucleon Transfer — local tree scan for recursive upload (F4.4).
// Pure Foundation: enumerates dropped files/folders into a flat entry list
// preserving structure via NFC-normalized relative paths. Symlink policy
// (TRANSFERS.md §1.2): followed when the target stays inside the scanned
// tree, skipped when it escapes (avoids loops/leaks); loops guarded by a
// visited-directory set. Hidden files are skipped.

import Foundation

enum LocalTreeScanError: Error, Sendable {
    case rootNotDirectory(String)
    case unreadable(String)
}

enum LocalTreeScan {
    struct Entry: Sendable, Equatable {
        /// Absolute local URL.
        var url: URL
        /// Path relative to the scan root, `/`-separated, NFC-normalized.
        /// The root itself is "".
        var relativePath: String
        var isDirectory: Bool
        /// File byte size (0 for directories).
        var size: Int64
        /// Security-scoped bookmark for a file, created during the
        /// detached scan while the drop's grant is held (F8.2-R2); nil for
        /// directories, in tests, or when bookmark creation failed.
        var bookmark: Data? = nil
    }

    struct Result: Sendable {
        /// Directories first, topological (parents before children), then files.
        var entries: [Entry]
        /// Symlinks skipped because they escape the tree.
        var skippedOutsideSymlinks: Int
        /// Directories skipped to break symlink loops.
        var skippedLoopDirs: Int
    }

    /// Re-roots a scan under the dropped folder's own name (F8.2-R6):
    /// "" → "Vacation", "a/b.txt" → "Vacation/a/b.txt". `enqueueTree`
    /// never creates the "" entry, so this is what makes dropping
    /// "Vacation" create `Vacation/` in the destination (its name conflict
    /// then follows FolderConflictPolicy like any other folder). A root
    /// name that cannot be a remote name ("", ".", "..", "/") leaves the
    /// entries unrooted.
    static func rooted(_ entries: [Entry], rootName: String) -> [Entry] {
        let name = rootName.precomposedStringWithCanonicalMapping
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else { return entries }
        return entries.map { entry in
            var e = entry
            e.relativePath = entry.relativePath.isEmpty ? name : name + "/" + entry.relativePath
            return e
        }
    }

    /// Adds a best-effort security-scoped bookmark to every file entry
    /// (F8.2-R2: created during the detached scan, so enqueue is a single
    /// batch instead of one queue save per file). Must run while the
    /// drop's security scope is held; failures leave `bookmark` nil.
    static func attachingBookmarks(_ entries: [Entry]) -> [Entry] {
        entries.map { entry in
            guard !entry.isDirectory else { return entry }
            var e = entry
            e.bookmark = try? entry.url.bookmarkData(
                options: .withSecurityScope,
                includingResourceValuesForKeys: nil,
                relativeTo: nil
            )
            return e
        }
    }

    /// Scans `root` (must be a directory). Deterministic: siblings sorted by name.
    static func collect(root: URL) throws -> Result {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir),
              isDir.boolValue
        else {
            throw LocalTreeScanError.rootNotDirectory(root.path)
        }
        let rootResolved = root.resolvingSymlinksInPath().standardized
        var entries: [Entry] = [Entry(url: root, relativePath: "", isDirectory: true, size: 0)]
        var skippedOutside = 0
        var skippedLoops = 0
        var visited: Set<String> = [rootResolved.path]

        // NOTE: relative paths are built structurally during recursion
        // (relPrefix + lastPathComponent), never by stripping the root prefix
        // off absolute strings — FileManager returns canonical paths
        // (/tmp → /private/tmp) that need not share a textual prefix with root.
        func nfc(_ s: String) -> String { s.precomposedStringWithCanonicalMapping }

        func walk(_ dir: URL, relPrefix: String) throws {
            let kids = try FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey],
                options: [.skipsHiddenFiles]
            ).sorted { $0.lastPathComponent < $1.lastPathComponent }
            for kid in kids {
                let rel = nfc(relPrefix.isEmpty ? kid.lastPathComponent : relPrefix + "/" + kid.lastPathComponent)
                let values = try? kid.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey])
                if values?.isSymbolicLink == true {
                    let target = kid.resolvingSymlinksInPath().standardized
                    // Outside the tree → skip (no leak, no loop).
                    guard target.path == rootResolved.path
                        || target.path.hasPrefix(rootResolved.path + "/")
                    else {
                        skippedOutside += 1
                        continue
                    }
                    var targetIsDir: ObjCBool = false
                    FileManager.default.fileExists(atPath: target.path, isDirectory: &targetIsDir)
                    if targetIsDir.boolValue {
                        guard !visited.contains(target.path) else {
                            skippedLoops += 1
                            continue
                        }
                        visited.insert(target.path)
                        entries.append(Entry(url: kid, relativePath: rel, isDirectory: true, size: 0))
                        try walk(target, relPrefix: rel)
                    } else {
                        let size = (try? target.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
                        entries.append(Entry(url: kid, relativePath: rel, isDirectory: false, size: size))
                    }
                    continue
                }
                if values?.isDirectory == true {
                    entries.append(Entry(url: kid, relativePath: rel, isDirectory: true, size: 0))
                    try walk(kid, relPrefix: rel)
                } else {
                    let size = Int64(values?.fileSize ?? 0)
                    entries.append(Entry(url: kid, relativePath: rel, isDirectory: false, size: size))
                }
            }
        }

        try walk(root, relPrefix: "")

        // Topological: directories by depth then path, then files by path.
        let dirs = entries.filter(\.isDirectory).sorted {
            let d0 = $0.relativePath.isEmpty ? 0 : $0.relativePath.components(separatedBy: "/").count
            let d1 = $1.relativePath.isEmpty ? 0 : $1.relativePath.components(separatedBy: "/").count
            if d0 != d1 { return d0 < d1 }
            return $0.relativePath < $1.relativePath
        }
        let files = entries.filter { !$0.isDirectory }.sorted { $0.relativePath < $1.relativePath }
        return Result(
            entries: dirs + files,
            skippedOutsideSymlinks: skippedOutside,
            skippedLoopDirs: skippedLoops
        )
    }
}
