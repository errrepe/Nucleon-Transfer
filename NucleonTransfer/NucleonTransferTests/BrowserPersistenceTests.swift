// Nucleon Transfer — F8.4-U4 browser state persistence (Swift Testing).
// Sidebar selection, last folder path and sort order round-trip through
// their stored strings; a stale saved path degrades to its valid prefix.
import Foundation
import Testing

@testable import NucleonTransfer

private func folder(_ id: String, in parent: String, name: String? = nil) -> DriveItem {
    DriveItem(
        id: id, shareID: "S", parentLinkID: parent, name: name ?? id,
        isNameDecrypted: true, kind: .folder, size: 0,
        modified: Date(timeIntervalSince1970: 1_700_000_000), mimeType: nil
    )
}

private func file(_ id: String, in parent: String) -> DriveItem {
    DriveItem(
        id: id, shareID: "S", parentLinkID: parent, name: id,
        isNameDecrypted: true, kind: .file, size: 1,
        modified: Date(timeIntervalSince1970: 1_700_000_000), mimeType: nil
    )
}

private let root = DriveLocation(shareID: "S", linkID: "R", name: "My Files")

/// Fake tree: R → A → B; R also holds file F.
private let tree: [String: [DriveItem]] = [
    "R": [folder("A", in: "R", name: "Alpha (renamed)"), file("F", in: "R")],
    "A": [folder("B", in: "A")],
    "B": [],
]

struct SidebarItemStorageTests {
    @Test func roundTrips() {
        for item in [SidebarItem.myFiles, .photos, .computer(shareID: "share-1:x")] {
            #expect(SidebarItem(storageValue: item.storageValue) == item)
        }
    }

    @Test func garbageIsNil() {
        #expect(SidebarItem(storageValue: "") == nil)
        #expect(SidebarItem(storageValue: "computer:") == nil)
        #expect(SidebarItem(storageValue: "trash") == nil)
    }
}

struct FolderPathRestorationTests {
    @Test func storesOnlyIDs() throws {
        let raw = FolderPathRestoration.encode(shareID: "S", path: [
            DriveLocation(shareID: "S", linkID: "A", name: "Secret Plans"),
        ])
        #expect(!raw.contains("Secret"))
        let saved = try #require(FolderPathRestoration.decode(raw))
        #expect(saved == .init(shareID: "S", linkIDs: ["A"]))
    }

    @Test func garbledStorageIsNil() {
        #expect(FolderPathRestoration.decode("") == nil)
        #expect(FolderPathRestoration.decode("{not json") == nil)
    }

    @Test func resolvesWithFreshNames() async {
        let path = await FolderPathRestoration.resolve(linkIDs: ["A", "B"], root: root) { tree[$0.linkID] }
        #expect(path.map(\.linkID) == ["A", "B"])
        #expect(path.first?.name == "Alpha (renamed)")
    }

    @Test func stopsAtFirstMissingFolder() async {
        let path = await FolderPathRestoration.resolve(linkIDs: ["A", "gone", "B"], root: root) { tree[$0.linkID] }
        #expect(path.map(\.linkID) == ["A"])
    }

    @Test func filesAreNotFolders() async {
        let path = await FolderPathRestoration.resolve(linkIDs: ["F"], root: root) { tree[$0.linkID] }
        #expect(path.isEmpty)
    }

    @Test func listingFailureStopsTheWalk() async {
        let path = await FolderPathRestoration.resolve(linkIDs: ["A", "B"], root: root) { loc in
            loc.linkID == "A" ? nil : tree[loc.linkID]
        }
        #expect(path.map(\.linkID) == ["A"])
    }

    @Test func depthIsCapped() throws {
        let deep = (0..<200).map { DriveLocation(shareID: "S", linkID: "L\($0)", name: "n") }
        let saved = try #require(FolderPathRestoration.decode(
            FolderPathRestoration.encode(shareID: "S", path: deep)
        ))
        #expect(saved.linkIDs.count == FolderPathRestoration.maxDepth)
    }
}

struct BrowserSortPreferenceTests {
    @Test func roundTripsEveryKey() {
        for key in BrowserSortPreference.Key.allCases {
            for ascending in [true, false] {
                let pref = BrowserSortPreference(key: key, ascending: ascending)
                #expect(BrowserSortPreference(rawValue: pref.rawValue) == pref)
            }
        }
        #expect(BrowserSortPreference(key: .modified, ascending: false).rawValue == "modified:desc")
    }

    @Test func rejectsGarbage() {
        #expect(BrowserSortPreference(rawValue: "") == nil)
        #expect(BrowserSortPreference(rawValue: "name") == nil)
        #expect(BrowserSortPreference(rawValue: "colour:asc") == nil)
        #expect(BrowserSortPreference(rawValue: "size:up") == nil)
        #expect(BrowserSortPreference.default == .init(key: .name, ascending: true))
    }
}
