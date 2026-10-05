// Nucleon Transfer — F8.2-R5 download robustness suite (Swift Testing).
// Case/normalization-only sibling collisions, non-destructive exclusive
// moves, cancellation (no temp file left, record cancelled not failed) and
// late progress on finished records. Offline: temp directories only.
import Foundation
import Testing

@testable import NucleonTransfer

struct DownloadPlacementTests {
    private func tempDir(_ prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func listing(_ dir: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
    }

    // MARK: - collisions

    @Test func caseVariantSiblingsBothSurviveInParallel() async throws {
        let dir = try tempDir("ntr5c")
        defer { try? FileManager.default.removeItem(at: dir) }
        let placement = DownloadPlacement()
        let inputs = [("A.txt", Data("upper".utf8)), ("a.txt", Data("lower".utf8))]
        let written = try await withThrowingTaskGroup(of: (Data, URL).self) { group in
            for (name, data) in inputs {
                group.addTask {
                    let url = try await placement.write(
                        data, in: dir, remoteName: name, fallback: "ID", root: dir
                    )
                    return (data, url)
                }
            }
            var out: [(Data, URL)] = []
            for try await pair in group { out.append(pair) }
            return out
        }
        #expect(written.count == 2)
        #expect(DownloadPlacement.folded(written[0].1.lastPathComponent)
            != DownloadPlacement.folded(written[1].1.lastPathComponent))
        for (data, url) in written {
            #expect(try Data(contentsOf: url) == data)
        }
        let names = try listing(dir)
        #expect(names.count == 2)
        #expect(!names.contains { $0.hasSuffix(FileDownload.partSuffix) })
        #expect(Set(names) == ["A.txt", "a (1).txt"] || Set(names) == ["a.txt", "A (1).txt"])
    }

    @Test func normalizationVariantSiblingsBothSurvive() async throws {
        let dir = try tempDir("ntr5n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let placement = DownloadPlacement()
        let nfc = "caf\u{E9}.txt"          // precomposed é
        let nfd = "cafe\u{301}.txt"        // e + combining acute
        let first = try await placement.write(Data("1".utf8), in: dir, remoteName: nfc, fallback: "X", root: dir)
        let second = try await placement.write(Data("2".utf8), in: dir, remoteName: nfd, fallback: "Y", root: dir)
        #expect(first != second)
        #expect(try Data(contentsOf: first) == Data("1".utf8))
        #expect(try Data(contentsOf: second) == Data("2".utf8))
        #expect(try listing(dir).count == 2)
    }

    @Test func caseVariantOnDiskIsNeverReplaced() async throws {
        let dir = try tempDir("ntr5d")
        defer { try? FileManager.default.removeItem(at: dir) }
        let existing = dir.appendingPathComponent("Report.TXT")
        try Data("mine".utf8).write(to: existing)
        let placement = DownloadPlacement()
        let url = try await placement.write(
            Data("remote".utf8), in: dir, remoteName: "report.txt", fallback: "ID", root: dir
        )
        // Case-insensitive volume → "report (1).txt"; case-sensitive → no
        // clash at all. Either way the user's file is untouched.
        #expect(try Data(contentsOf: existing) == Data("mine".utf8))
        #expect(try Data(contentsOf: url) == Data("remote".utf8))
        #expect(try listing(dir).count == 2)
    }

    @Test func foldersDifferingByCaseGetDistinctNames() async throws {
        let dir = try tempDir("ntr5f")
        defer { try? FileManager.default.removeItem(at: dir) }
        let placement = DownloadPlacement()
        let docs = try await placement.makeDirectory(in: dir, remoteName: "Docs", fallback: "A", root: dir)
        let lower = try await placement.makeDirectory(in: dir, remoteName: "docs", fallback: "B", root: dir)
        #expect(docs.lastPathComponent == "Docs")
        #expect(lower.lastPathComponent == "docs (1)")
        // A file named like a sibling folder (any case) gets its own name.
        let file = try await placement.write(Data("f".utf8), in: dir, remoteName: "DOCS", fallback: "C", root: dir)
        #expect(file.lastPathComponent == "DOCS (2)")
        #expect(try listing(dir).count == 3)
    }

    @Test func makeDirectoryNeverMergesIntoExistingFolder() async throws {
        let dir = try tempDir("ntr5m")
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(
            at: dir.appendingPathComponent("Vacation"), withIntermediateDirectories: false
        )
        let placement = DownloadPlacement()
        let made = try await placement.makeDirectory(in: dir, remoteName: "Vacation", fallback: "V", root: dir)
        #expect(made.lastPathComponent == "Vacation (1)")
        let escape = try await placement.makeDirectory(in: dir, remoteName: "..", fallback: "FOLDERID", root: dir)
        #expect(escape.lastPathComponent == "FOLDERID")
        #expect(SafeFilename.contained(escape, in: dir))
    }

    // MARK: - top-level folder (F8.2-R6)

    @Test func folderDownloadCreatesItsOwnFolder() async throws {
        let dest = try tempDir("ntr6")
        defer { try? FileManager.default.removeItem(at: dest) }
        try Data("user".utf8).write(to: dest.appendingPathComponent("notes.txt"))
        let placement = DownloadPlacement()
        // Mirrors DriveDownloadAdapter.downloadTree for a folder link.
        let top = try await placement.makeTopLevelDirectory(in: dest, remoteName: "Vacation", fallback: "LINKID")
        #expect(top.lastPathComponent == "Vacation")
        #expect(top.deletingLastPathComponent().standardizedFileURL.path
            == dest.standardizedFileURL.path)
        let photo = try await placement.write(
            Data("jpg".utf8), in: top, remoteName: "beach.jpg", fallback: "F", root: dest
        )
        #expect(photo.path.hasSuffix("/Vacation/beach.jpg"))
        // Children went into Vacation/, not next to the user's files.
        #expect(try listing(dest) == ["Vacation", "notes.txt"])
        #expect(try listing(top) == ["beach.jpg"])
    }

    @Test func folderDownloadNeverMergesIntoExistingFolder() async throws {
        let dest = try tempDir("ntr6m")
        defer { try? FileManager.default.removeItem(at: dest) }
        let mine = dest.appendingPathComponent("Vacation", isDirectory: true)
        try FileManager.default.createDirectory(at: mine, withIntermediateDirectories: false)
        try Data("keep".utf8).write(to: mine.appendingPathComponent("beach.jpg"))
        // A FILE with the folder's name (other case) also blocks the name.
        try Data("f".utf8).write(to: dest.appendingPathComponent("VACATION (1)"))
        let placement = DownloadPlacement()
        let top = try await placement.makeTopLevelDirectory(in: dest, remoteName: "Vacation", fallback: "LINKID")
        #expect(top.lastPathComponent == "Vacation (2)" || top.lastPathComponent == "Vacation (1)")
        #expect(try listing(top).isEmpty)
        #expect(try listing(mine) == ["beach.jpg"])
        #expect(try Data(contentsOf: mine.appendingPathComponent("beach.jpg")) == Data("keep".utf8))
        // Second download of the same folder in the same batch: new folder again.
        let again = try await placement.makeTopLevelDirectory(in: dest, remoteName: "vacation", fallback: "LINKID")
        #expect(again != top)
        #expect(again.lastPathComponent.hasPrefix("vacation ("))
    }

    @Test func topLevelFolderNameIsSanitizedAndContained() async throws {
        let parent = try tempDir("ntr6s")
        defer { try? FileManager.default.removeItem(at: parent) }
        let dest = parent.appendingPathComponent("chosen", isDirectory: true)
        try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: false)
        let placement = DownloadPlacement()
        let dots = try await placement.makeTopLevelDirectory(in: dest, remoteName: "..", fallback: "LINKID")
        #expect(dots.lastPathComponent == "LINKID")
        let traversal = try await placement.makeTopLevelDirectory(
            in: dest, remoteName: "../../Library", fallback: "LINKID"
        )
        #expect(traversal.lastPathComponent == ".._.._Library")
        for url in [dots, traversal] {
            #expect(SafeFilename.contained(url, in: dest))
        }
        #expect(try listing(parent) == ["chosen"])
    }

    // MARK: - non-destructive move

    @Test func moveExclusiveRefusesExistingDestination() throws {
        let dir = try tempDir("ntr5x")
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = dir.appendingPathComponent("src")
        let dst = dir.appendingPathComponent("dst")
        try Data("new".utf8).write(to: src)
        try Data("old".utf8).write(to: dst)
        #expect(try FileDownload.moveExclusive(src, to: dst) == false)
        #expect(try Data(contentsOf: dst) == Data("old".utf8))
        #expect(FileManager.default.fileExists(atPath: src.path))
        let free = dir.appendingPathComponent("free")
        #expect(try FileDownload.moveExclusive(src, to: free))
        #expect(!FileManager.default.fileExists(atPath: src.path))
        #expect(try Data(contentsOf: free) == Data("new".utf8))
    }

    @Test func existingDestinationAtMoveTimeGetsSuffix() throws {
        let dir = try tempDir("ntr5s")
        defer { try? FileManager.default.removeItem(at: dir) }
        // The destination was planned free, then something appeared there
        // before the move: atomicWrite picks the next name, never replaces.
        let planned = dir.appendingPathComponent("x.txt")
        try Data("appeared".utf8).write(to: planned)
        let final = try FileDownload.atomicWrite(Data("download".utf8), to: planned)
        #expect(final.lastPathComponent == "x (1).txt")
        #expect(try Data(contentsOf: planned) == Data("appeared".utf8))
        #expect(try Data(contentsOf: final) == Data("download".utf8))
        #expect(try listing(dir) == ["x (1).txt", "x.txt"])
    }

    @Test func partNamesAreUniqueHiddenAndBounded() throws {
        let dir = try tempDir("ntr5p")
        defer { try? FileManager.default.removeItem(at: dir) }
        let long = SafeFilename.sanitize(String(repeating: "q", count: 300) + ".bin", fallback: "F")
        let a = try FileDownload.writePart(Data("1".utf8), in: dir, name: long)
        let b = try FileDownload.writePart(Data("2".utf8), in: dir, name: long)
        #expect(a != b)
        for part in [a, b] {
            #expect(part.lastPathComponent.hasPrefix("."))
            #expect(part.lastPathComponent.hasSuffix(FileDownload.partSuffix))
            #expect(part.lastPathComponent.utf8.count <= SafeFilename.maxBytes)
        }
    }

    // MARK: - cancellation

    @Test func cancelledWriteLeavesNothingBehind() async throws {
        let dir = try tempDir("ntr5k")
        defer { try? FileManager.default.removeItem(at: dir) }
        let placement = DownloadPlacement()
        let task = Task {
            // Stand-in for the block fetch: runs until cancelled, then the
            // adapter's next step (placing the bytes) must refuse.
            while !Task.isCancelled { await Task.yield() }
            return try await placement.write(
                Data("partial".utf8), in: dir, remoteName: "big.iso", fallback: "ID", root: dir
            )
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("cancelled write succeeded")
        } catch {
            #expect(DownloadRecord.isCancellation(error))
        }
        #expect(try listing(dir).isEmpty)
        // The released reservation does not leak a suffix onto the retry.
        let retry = try await placement.write(
            Data("full".utf8), in: dir, remoteName: "big.iso", fallback: "ID", root: dir
        )
        #expect(retry.lastPathComponent == "big.iso")
    }

    @Test func cancellationErrorsAreRecognized() {
        #expect(DownloadRecord.isCancellation(CancellationError()))
        #expect(DownloadRecord.isCancellation(URLError(.cancelled)))
        #expect(DownloadRecord.isCancellation(ProtonAPIError.transport(URLError(.cancelled))))
        #expect(!DownloadRecord.isCancellation(URLError(.timedOut)))
        #expect(!DownloadRecord.isCancellation(FileDownloadError.hashMismatch(index: 1)))
    }

    @Test func cancelledRecordIsCancelledNotFailed() {
        var rec = DownloadRecord(name: "big.iso", kind: .file, progress: 0.3)
        let changed1 = rec.cancel()
        #expect(changed1)
        #expect(rec.state == .cancelled)
        #expect(rec.progress == nil)
        #expect(rec.errorMessage == nil)
        #expect(rec.stateLabel == "Cancelled")
        // A failure or completion racing in after the cancel is ignored.
        let changed2 = rec.fail(message: "boom")
        #expect(!changed2)
        let changed3 = rec.finish(fileCount: 1, destinationName: "D")
        #expect(!changed3)
        #expect(rec.state == .cancelled)
        let item = TransferDisplay.item(for: rec)
        #expect(item.subtitle == "Cancelled")
        #expect(!item.isFailed)
        #expect(!item.isActive)
        #expect(TransferDisplay.section(of: rec) == .failed)
        #expect(TransferDisplay.activeCount(uploads: [], downloads: [rec]) == 0)
    }

    @Test func lateProgressIsIgnored() {
        var rec = DownloadRecord(name: "a.bin", kind: .file)
        let changed4 = rec.applyProgress(0.5)
        #expect(changed4)
        #expect(rec.progress == 0.5)
        let changed5 = rec.applyProgress(7)
        #expect(changed5)
        #expect(rec.progress == 1)
        let changed6 = rec.finish(fileCount: 1, destinationName: "Out")
        #expect(changed6)
        #expect(rec.progress == nil)
        // The unstructured progress hop lands after downloadFinished.
        let changed7 = rec.applyProgress(0.75)
        #expect(!changed7)
        #expect(rec.progress == nil)
        #expect(rec.state == .done)
        var cancelled = DownloadRecord(name: "b.bin", kind: .file)
        cancelled.cancel()
        let changed8 = cancelled.applyProgress(0.2)
        #expect(!changed8)
        #expect(cancelled.progress == nil)
    }

    @Test func cancelledStateDecodes() throws {
        let rec = DownloadRecord(name: "c.bin", kind: .file, state: .cancelled)
        let back = try JSONDecoder().decode(DownloadRecord.self, from: try JSONEncoder().encode(rec))
        #expect(back.state == .cancelled)
        #expect(back.summary == "Download cancelled")
    }
}
