// Nucleon Transfer — F8.1-S5 remote-name sanitizing suite (Swift Testing).
// Untrusted decrypted names ("..", "a/b", NUL, NFD, overlong) must become a
// single safe path component, and download destinations built from them
// must stay inside the folder the user chose (incl. symlink escapes).
import Foundation
import Testing

@testable import NucleonTransfer

struct SafeFilenameTests {
    private let fb = "LINKID=="

    @Test func dotNamesAndEmptyMapToFallback() {
        #expect(SafeFilename.sanitize("..", fallback: fb) == fb)
        #expect(SafeFilename.sanitize(".", fallback: fb) == fb)
        #expect(SafeFilename.sanitize("", fallback: fb) == fb)
        // Only control chars → empty after stripping → fallback.
        #expect(SafeFilename.sanitize("\u{0}\u{1F}", fallback: fb) == fb)
        // ".\u{0}." collapses to ".." → fallback, never "..".
        #expect(SafeFilename.sanitize(".\u{0}.", fallback: fb) == fb)
    }

    @Test func unusableFallbackFallsToLastResort() {
        #expect(SafeFilename.sanitize("..", fallback: "") == SafeFilename.lastResort)
        #expect(SafeFilename.sanitize(".", fallback: "..") == SafeFilename.lastResort)
        // A fallback is sanitized too (IDs may contain "/").
        #expect(SafeFilename.sanitize("", fallback: "ab/cd==") == "ab_cd==")
    }

    @Test func separatorsReplaced() {
        #expect(SafeFilename.sanitize("a/b", fallback: fb) == "a_b")
        #expect(SafeFilename.sanitize("a:b", fallback: fb) == "a_b")
        #expect(SafeFilename.sanitize("../../x", fallback: fb) == ".._.._x")
        #expect(SafeFilename.sanitize("/", fallback: fb) == "_")
        let evil = SafeFilename.sanitize("../../Library/LaunchAgents/x.plist", fallback: fb)
        #expect(!evil.contains("/"))
        #expect(evil == ".._.._Library_LaunchAgents_x.plist")
    }

    @Test func controlCharactersStripped() {
        #expect(SafeFilename.sanitize("x\u{0}y", fallback: fb) == "xy")
        #expect(SafeFilename.sanitize("a\nb\tc\u{7F}d", fallback: fb) == "abcd")
    }

    @Test func normalNamesUnchanged() {
        for name in ["report.pdf", "Férias 2026", ".hidden", "a b.tar.gz",
                     "日本語.txt", "emoji 👩‍👩‍👧.png", "trailing.", "space ", "...", "-x"] {
            #expect(SafeFilename.sanitize(name, fallback: fb) == name)
        }
    }

    @Test func nfdInputBecomesNFC() {
        let nfd = "Fe\u{301}rias" // e + combining acute
        let out = SafeFilename.sanitize(nfd, fallback: fb)
        #expect(out == "F\u{E9}rias")
        #expect(out.unicodeScalars.count == 6)
        // A control char between base and mark still recomposes.
        #expect(SafeFilename.sanitize("e\u{0}\u{301}", fallback: fb) == "\u{E9}")
    }

    @Test func longNamesCappedPreservingExtension() {
        let long = String(repeating: "a", count: 400) + ".txt"
        let out = SafeFilename.sanitize(long, fallback: fb)
        #expect(out.utf8.count == 255)
        #expect(out.hasSuffix(".txt"))
        // Multi-byte: never split a scalar/grapheme, still ≤ 255 bytes.
        let wide = String(repeating: "é", count: 200) + ".jpeg" // 2 bytes each
        let w = SafeFilename.sanitize(wide, fallback: fb)
        #expect(w.utf8.count <= 255)
        #expect(w.hasSuffix(".jpeg"))
        #expect(w.dropLast(5).allSatisfy { $0 == "é" })
        // Overlong "extension" is not preserved — plain truncation.
        let weird = "a." + String(repeating: "b", count: 300)
        #expect(SafeFilename.sanitize(weird, fallback: fb).utf8.count == 255)
        // Hidden file name stays hidden when truncated.
        let hidden = "." + String(repeating: "h", count: 300)
        let h = SafeFilename.sanitize(hidden, fallback: fb)
        #expect(h.hasPrefix(".") && h.utf8.count == 255)
    }

    @Test func uniqueDestinationSuffixFitsLimit() throws {
        let dir = try tempDir("ntsfu")
        defer { try? FileManager.default.removeItem(at: dir) }
        let name = SafeFilename.sanitize(String(repeating: "z", count: 300) + ".bin", fallback: fb)
        try Data("1".utf8).write(to: dir.appendingPathComponent(name))
        let next = FileDownload.uniqueDestination(in: dir, name: name).lastPathComponent
        #expect(next.utf8.count <= 255)
        #expect(next.hasSuffix(" (1).bin"))
        // Short names keep the exact previous behavior.
        try Data("1".utf8).write(to: dir.appendingPathComponent("a.txt"))
        #expect(FileDownload.uniqueDestination(in: dir, name: "a.txt").lastPathComponent == "a (1).txt")
    }

    // MARK: - containment

    @Test func containedRejectsEscapes() throws {
        let root = try tempDir("ntsfc")
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(SafeFilename.contained(root.appendingPathComponent("a"), in: root))
        #expect(SafeFilename.contained(root.appendingPathComponent("a/b/c.txt"), in: root))
        #expect(!SafeFilename.contained(root, in: root))
        #expect(!SafeFilename.contained(root.appendingPathComponent(".."), in: root))
        #expect(!SafeFilename.contained(root.appendingPathComponent("../x"), in: root))
        #expect(!SafeFilename.contained(root.appendingPathComponent("a/../../x"), in: root))
        // Sibling with a shared string prefix is NOT inside.
        let sibling = URL(fileURLWithPath: root.path + "-evil")
        #expect(!SafeFilename.contained(sibling.appendingPathComponent("x"), in: root))
    }

    @Test func containedFollowsSymlinks() throws {
        let root = try tempDir("ntsfr")
        let outside = try tempDir("ntsfo")
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: outside)
        }
        let link = root.appendingPathComponent("escape")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        #expect(!SafeFilename.contained(link.appendingPathComponent("x.plist"), in: root))
        do {
            _ = try FileDownload.safeFileDestination(
                in: link, remoteName: "x.plist", fallback: fb, root: root
            )
            Issue.record("symlink escape accepted")
        } catch let e as FileDownloadError {
            #expect(e == .unsafeDestination)
        }
    }

    /// Mirrors DriveDownloadAdapter.downloadFolder: a malicious remote tree
    /// (folder "..", nested "../../" child, file "../../Library/…/x.plist")
    /// lands entirely inside the chosen destination.
    @Test func maliciousTreeLandsInsideDestination() throws {
        let parent = try tempDir("ntsft")
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("chosen", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        let sub = try FileDownload.safeSubdirectory(
            in: root, remoteName: "..", fallback: "FOLDERID", root: root
        )
        #expect(sub.lastPathComponent == "FOLDERID")
        let nested = try FileDownload.safeSubdirectory(
            in: sub, remoteName: "../../..", fallback: "N", root: root
        )
        var written: [URL] = []
        for (dir, name) in [
            (root, "../../Library/LaunchAgents/x.plist"),
            (sub, ".."),
            (nested, "../escape.txt"),
            (nested, "a:b\u{0}.txt"),
        ] {
            let dest = try FileDownload.safeFileDestination(
                in: dir, remoteName: name, fallback: "FILEID", root: root
            )
            try FileDownload.atomicWrite(Data("x".utf8), to: dest)
            written.append(dest)
        }
        for url in written {
            #expect(SafeFilename.contained(url, in: root))
            #expect(FileManager.default.fileExists(atPath: url.path))
        }
        // Nothing appeared next to the chosen folder.
        let siblings = try FileManager.default.contentsOfDirectory(atPath: parent.path)
        #expect(siblings == ["chosen"])
        #expect(written.map(\.lastPathComponent) == [
            ".._.._Library_LaunchAgents_x.plist", "FILEID", ".._escape.txt", "a_b.txt",
        ])
    }

    private func tempDir(_ prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}
