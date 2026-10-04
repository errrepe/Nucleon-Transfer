// Nucleon Transfer — remote-name sanitizing for local writes (F8.1-S5).
// Decrypted Drive names are attacker-controlled (any collaborator or other
// client can set them, and the server cannot validate encrypted names), so
// a name like ".." or "../../Library/LaunchAgents/x.plist" must never reach
// appendingPathComponent unfiltered. Every remote name that becomes a local
// path component goes through `sanitize`, and every built destination is
// re-checked with `contained` against the user's chosen root (defense in
// depth: the second check also catches symlinks already on disk).
//
// Rules (sanitize):
//   - NFC (precomposed) — matches what Finder/upload produce.
//   - "/" and ":" become "_" (ASCII, visibly a substitute; a look-alike such
//     as U+2215 would let "a∕b" pose as a path in the UI).
//   - C0 controls (U+0000–U+001F, incl. NUL) and DEL are dropped.
//   - Leading dots are kept (hidden files are legitimate); trailing spaces
//     and dots are kept too (valid on APFS/HFS+, and part of the user's name).
//   - Exactly "", "." or ".." (after the steps above) → the fallback (the
//     link ID, itself sanitized; "download" if that is unusable too).
//   - At most 255 UTF-8 bytes (APFS limit), truncating the stem on grapheme
//     boundaries and preserving a short extension.

import Foundation

enum SafeFilename {
    /// APFS / HFS+ max file-name length, in UTF-8 bytes.
    static let maxBytes = 255
    /// Extensions longer than this are treated as part of the stem when
    /// truncating (a 200-byte "extension" is not worth preserving).
    static let maxExtensionBytes = 32
    /// Substitute for path separators ("/" and the HFS separator ":").
    static let separatorSubstitute: Character = "_"
    /// Last-resort name when both the remote name and fallback are unusable.
    static let lastResort = "download"

    /// Returns a single, safe local path component for a remote name.
    static func sanitize(_ remote: String, fallback: String) -> String {
        if let name = clean(remote) { return name }
        if let name = clean(fallback) { return name }
        return lastResort
    }

    /// True when `url` (after standardizing ".." and resolving symlinks of
    /// its existing ancestors) lies strictly inside `root`.
    static func contained(_ url: URL, in root: URL) -> Bool {
        let r = resolved(root).pathComponents
        let u = resolved(url).pathComponents
        return u.count > r.count && Array(u.prefix(r.count)) == r
    }

    /// Caps `name` at `maxBytes` UTF-8 bytes, preserving a short extension.
    /// Used by sanitize, and by FileDownload.uniqueDestination to leave room
    /// for a " (n)" conflict suffix.
    static func capped(_ name: String, maxBytes limit: Int = maxBytes) -> String {
        guard name.utf8.count > limit else { return name }
        let ns = name as NSString
        let ext = ns.pathExtension
        // "a.txt" has ext "txt"; ".hidden" has none (pathExtension is "").
        if !ext.isEmpty, ext.utf8.count <= maxExtensionBytes, ext.utf8.count + 2 <= limit {
            let stem = truncate(ns.deletingPathExtension, toBytes: limit - ext.utf8.count - 1)
            if !stem.isEmpty { return stem + "." + ext }
        }
        return truncate(name, toBytes: limit)
    }

    // MARK: - private

    /// Applies the character rules; nil when the result is unusable.
    private static func clean(_ raw: String) -> String? {
        var out = ""
        for scalar in raw.precomposedStringWithCanonicalMapping.unicodeScalars {
            switch scalar.value {
            case 0x00...0x1F, 0x7F:
                continue
            case 0x2F, 0x3A: // "/" ":"
                out.append(separatorSubstitute)
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        // Re-normalize: dropping a control between a base and a combining
        // mark can create a new composable pair.
        let name = capped(out.precomposedStringWithCanonicalMapping)
        guard !name.isEmpty, name != ".", name != ".." else { return nil }
        return name
    }

    /// Longest prefix of whole grapheme clusters within `bytes` UTF-8 bytes.
    private static func truncate(_ s: String, toBytes bytes: Int) -> String {
        var out = ""
        var used = 0
        for ch in s {
            let n = ch.utf8.count
            if used + n > bytes { break }
            out.append(ch)
            used += n
        }
        return out
    }

    /// Standardized URL with the symlinks of its deepest existing ancestor
    /// resolved (the leaf may not exist yet — we check before writing).
    private static func resolved(_ url: URL) -> URL {
        var existing = url.standardizedFileURL
        var tail: [String] = []
        let fm = FileManager.default
        while !fm.fileExists(atPath: existing.path), existing.pathComponents.count > 1 {
            tail.insert(existing.lastPathComponent, at: 0)
            existing = existing.deletingLastPathComponent()
        }
        var out = existing.resolvingSymlinksInPath()
        for component in tail {
            out.appendPathComponent(component)
        }
        return out
    }
}
