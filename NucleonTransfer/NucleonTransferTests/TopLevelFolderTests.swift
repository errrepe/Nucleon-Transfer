// Nucleon Transfer — F8.2-R6 upload keeps the dropped top-level folder
// (Swift Testing). LocalTreeScan.rooted + enqueueTree with folder fakes.
import Foundation
import Testing

@testable import NucleonTransfer

private func entry(_ rel: String, dir: Bool, root: URL = URL(fileURLWithPath: "/drop")) -> LocalTreeScan.Entry {
    LocalTreeScan.Entry(url: root.appendingPathComponent(rel), relativePath: rel, isDirectory: dir, size: dir ? 0 : 5)
}

struct TopLevelFolderTests {
    @Test func rootedPrefixesEveryEntryWithTheFolderName() {
        let scanned = [entry("", dir: true), entry("sub", dir: true), entry("a.txt", dir: false), entry("sub/b.txt", dir: false)]
        let rooted = LocalTreeScan.rooted(scanned, rootName: "Vacation")
        #expect(rooted.map(\.relativePath) == ["Vacation", "Vacation/sub", "Vacation/a.txt", "Vacation/sub/b.txt"])
        #expect(rooted.map(\.isDirectory) == scanned.map(\.isDirectory))
        #expect(rooted.map(\.url) == scanned.map(\.url)) // local URLs untouched
    }

    @Test func rootNameIsNFCNormalized() {
        let nfd = "Fe\u{0301}rias" // "Férias" decomposed
        let rooted = LocalTreeScan.rooted([entry("", dir: true)], rootName: nfd)
        #expect(rooted[0].relativePath == "F\u{00E9}rias")
    }

    @Test func unusableRootNamesLeaveEntriesUnrooted() {
        let scanned = [entry("", dir: true), entry("a.txt", dir: false)]
        for bad in ["", ".", "..", "/"] {
            #expect(LocalTreeScan.rooted(scanned, rootName: bad).map(\.relativePath) == ["", "a.txt"])
        }
    }

    @Test func droppedFolderIsCreatedInDestination() async throws {
        let folders = MockFolders()
        let (q, _) = await makeQueue()
        let scanned = [entry("", dir: true), entry("sub", dir: true), entry("a.txt", dir: false), entry("sub/b.txt", dir: false)]
        try await q.enqueueTree(
            entries: LocalTreeScan.rooted(scanned, rootName: "Vacation"),
            shareID: "S", rootParentLinkID: "DEST", folders: folders
        )
        #expect(folders.calls.map(\.name) == ["Vacation", "sub"])
        #expect(folders.calls[0].parent == "DEST")
        #expect(folders.calls[1].parent == "L-Vacation")
        let byRel = Dictionary(uniqueKeysWithValues: await q.snapshot().map { ($0.relativePath, $0) })
        #expect(byRel["Vacation/a.txt"]?.parentLinkID == "L-Vacation")
        #expect(byRel["Vacation/a.txt"]?.fileName == "a.txt")
        #expect(byRel["Vacation/sub/b.txt"]?.parentLinkID == "L-sub")
    }

    @Test func emptyDroppedFolderIsStillCreated() async throws {
        let folders = MockFolders()
        let (q, _) = await makeQueue()
        let ids = try await q.enqueueTree(
            entries: LocalTreeScan.rooted([entry("", dir: true)], rootName: "Empty"),
            shareID: "S", rootParentLinkID: "DEST", folders: folders
        )
        #expect(ids.isEmpty)
        #expect(folders.calls.map(\.name) == ["Empty"])
    }

    @Test func multipleDropsKeepTheirOwnRootsAndLooseFilesStayFlat() async throws {
        let folders = MockFolders()
        let (q, _) = await makeQueue()
        // Two folders + one loose file, as UploadCoordinator enqueues them.
        try await q.enqueueTree(
            entries: LocalTreeScan.rooted([entry("", dir: true), entry("x.txt", dir: false)], rootName: "One"),
            shareID: "S", rootParentLinkID: "DEST", folders: folders
        )
        try await q.enqueueTree(
            entries: LocalTreeScan.rooted([entry("", dir: true), entry("x.txt", dir: false)], rootName: "Two"),
            shareID: "S", rootParentLinkID: "DEST", folders: folders
        )
        try await q.enqueueTree(
            entries: [entry("loose.txt", dir: false)],
            shareID: "S", rootParentLinkID: "DEST", folders: folders
        )
        #expect(folders.calls.map(\.name) == ["One", "Two"])
        #expect(folders.calls.allSatisfy { $0.parent == "DEST" })
        let byRel = Dictionary(uniqueKeysWithValues: await q.snapshot().map { ($0.relativePath, $0.parentLinkID) })
        #expect(byRel["One/x.txt"] == "L-One")
        #expect(byRel["Two/x.txt"] == "L-Two")
        #expect(byRel["loose.txt"] == "DEST")
    }

    @Test func realScanRootedUnderFolderName() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("ntroot-\(UUID().uuidString)")
        let root = parent.appendingPathComponent("Vacation")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("day1"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        try Data("x".utf8).write(to: root.appendingPathComponent("day1/pic.jpg"))
        let rooted = LocalTreeScan.rooted(try LocalTreeScan.collect(root: root).entries, rootName: root.lastPathComponent)
        let rels = rooted.map(\.relativePath)
        #expect(rels.first == "Vacation")
        #expect(rels.contains("Vacation/day1"))
        #expect(rels.contains("Vacation/day1/pic.jpg"))
    }
}
