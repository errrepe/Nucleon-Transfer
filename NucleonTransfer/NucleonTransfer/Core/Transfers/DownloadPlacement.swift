// Nucleon Transfer — race-free local names for one download batch (F8.2-R5).
// Proton allows siblings that differ only by case or Unicode normalization
// ("A.txt" / "a.txt"); the default APFS volume treats them as ONE name.
// Parallel file tasks used to pick a name check-then-act and then replace
// whatever was there, so one sibling silently deleted the other, and
// "Docs" / "docs" merged. This actor serializes the NAME choice:
//   - every chosen name is reserved under a case- and normalization-folded
//     key per directory, so in-flight siblings never pick the same name;
//   - bytes go to a unique `.<name>.<uuid>.nucleon-part`, then move with an
//     EXCLUSIVE rename (FileDownload.moveExclusive) — never a remove; a
//     name taken at move time (another app, a case variant) gets the next
//     free " (n)" and the move is retried;
//   - folders are created exclusively too: case-only siblings get distinct
//     local names ("docs (1)") instead of merging;
//   - the temp file is removed on any failure, cancellation included.
// Disk I/O for the bytes runs outside the actor (only the cheap name
// bookkeeping is serialized). Sanitize + containment stay in FileDownload.

import Foundation

actor DownloadPlacement {
    /// Folded directory path → folded names reserved in it.
    private var reserved: [String: Set<String>] = [:]
    /// Exclusive-move / mkdir attempts before giving up.
    private let maxAttempts = 64

    /// Comparison key matching the default (case-insensitive,
    /// normalization-insensitive) APFS behavior.
    static func folded(_ name: String) -> String {
        name.precomposedStringWithCanonicalMapping
            .folding(options: [.caseInsensitive], locale: nil)
            .lowercased()
    }

    // MARK: - files

    /// Places `data` under a free name for `remoteName` in `directory`
    /// (sanitized, contained in `root`). Returns the final URL. Throws
    /// CancellationError (and leaves no temp file) if the task is cancelled
    /// before the move.
    nonisolated func write(
        _ data: Data, in directory: URL, remoteName: String, fallback: String, root: URL
    ) async throws -> URL {
        try Task.checkCancellation()
        let name = SafeFilename.sanitize(remoteName, fallback: fallback)
        var dest = try await reserveFile(in: directory, remoteName: remoteName, fallback: fallback, root: root)
        let part: URL
        do {
            part = try FileDownload.writePart(data, in: directory, name: name)
        } catch {
            await release(dest)
            throw error
        }
        do {
            for _ in 0..<maxAttempts {
                try Task.checkCancellation()
                if try FileDownload.moveExclusive(part, to: dest) { return dest }
                // Taken at move time (outside our reservations): keep the
                // old key reserved — it is occupied — and pick the next one.
                dest = try await reserveFile(in: directory, remoteName: remoteName, fallback: fallback, root: root)
            }
            throw FileDownloadError.destinationUnavailable
        } catch {
            try? FileManager.default.removeItem(at: part)
            await release(dest)
            throw error
        }
    }

    /// Chooses + reserves a free file name (never on disk, never reserved
    /// by a sibling still in flight).
    func reserveFile(in directory: URL, remoteName: String, fallback: String, root: URL) throws -> URL {
        let dest = try FileDownload.safeFileDestination(
            in: directory, remoteName: remoteName, fallback: fallback, root: root,
            isTaken: { self.isTaken($0) }
        )
        reserve(dest)
        return dest
    }

    // MARK: - folders

    /// Creates a NEW local folder for `remoteName` in `directory` —
    /// sanitized, contained in `root`, " (n)"-suffixed when the name (in
    /// any case) is on disk or reserved. Never merges into an existing
    /// folder.
    func makeDirectory(in directory: URL, remoteName: String, fallback: String, root: URL) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for _ in 0..<maxAttempts {
            try Task.checkCancellation()
            let dest = try FileDownload.safeSubdirectory(
                in: directory, remoteName: remoteName, fallback: fallback, root: root,
                isTaken: { self.isTaken($0) }
            )
            do {
                // Without intermediates mkdir is exclusive: an item that
                // appeared since the check makes it throw.
                try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: false)
                reserve(dest)
                return dest
            } catch {
                guard FileDownload.itemExists(at: dest) else { throw error }
                reserve(dest) // occupied by someone else; try the next suffix
            }
        }
        throw FileDownloadError.destinationUnavailable
    }

    // MARK: - bookkeeping

    private func isTaken(_ url: URL) -> Bool {
        if reserved[Self.directoryKey(url)]?.contains(Self.folded(url.lastPathComponent)) == true {
            return true
        }
        return FileDownload.itemExists(at: url)
    }

    private func reserve(_ url: URL) {
        reserved[Self.directoryKey(url), default: []].insert(Self.folded(url.lastPathComponent))
    }

    private func release(_ url: URL) {
        reserved[Self.directoryKey(url)]?.remove(Self.folded(url.lastPathComponent))
    }

    private static func directoryKey(_ url: URL) -> String {
        folded(url.deletingLastPathComponent().standardizedFileURL.path)
    }
}
