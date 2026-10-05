// Nucleon Transfer — DEBUG-only offline demo drive for QA + screenshots (R1).
// A fixed tree behind DriveListingProviding with ~250 ms of fake latency so
// loading states render; "Broken Folder" throws a transport error to reach
// the browser's error state. No network, no keys — signing out of demo lands
// on the normal login screen.
#if DEBUG
import Foundation

/// 2026-09-01T00:00:00Z — every row's `modified` counts days from here so
/// the tree is deterministic across runs.
private let demoEpoch = Date(timeIntervalSince1970: 1_788_220_800)

/// ~120 characters — exercises long-name truncation in the table.
private let demoLongFileName =
    "2026-09-01 quarterly review — consolidated notes, appendices and " +
    "references for the board meeting (final version 3).txt"

private func demoFolder(_ id: String, _ name: String, in parent: String,
                        share: String, days: Int) -> DriveItem {
    DriveItem(
        id: id, shareID: share, parentLinkID: parent,
        name: name, isNameDecrypted: true, kind: .folder, size: 0,
        modified: demoEpoch.addingTimeInterval(TimeInterval(days * 86_400)),
        mimeType: nil
    )
}

private func demoFile(_ id: String, _ name: String, in parent: String,
                      share: String, size: Int64, days: Int, mime: String?,
                      decrypted: Bool = true) -> DriveItem {
    DriveItem(
        id: id, shareID: share, parentLinkID: parent,
        name: name, isNameDecrypted: decrypted, kind: .file, size: size,
        modified: demoEpoch.addingTimeInterval(TimeInterval(days * 86_400)),
        mimeType: mime
    )
}

/// Offline listing fixture: deterministic tree, fixed dates, artificial
/// latency. Core can't see Features/PreviewFixtures, so the three DriveRoot
/// values are duplicated here with the same IDs the previews use. Stable
/// link IDs (`demo-projects`, `demo-client-a`, …) let QA reports cite rows
/// unambiguously.
actor DemoDriveListing: DriveListingProviding {
    /// Fake per-call latency so progress states actually render.
    private static let latency = Duration.milliseconds(250)
    /// children(of:) on this folder always throws (error-state coverage).
    private static let brokenFolderID = "demo-broken"

    /// Same share/link IDs as PreviewFixtures.roots, minus Computer 2.
    private let demoRoots = DriveRoots(
        myFiles: DriveRoot(
            shareID: "share-main", rootLinkID: "link-main-root",
            volumeID: "vol-main", kind: .main,
            displayName: String(localized: "My Files", comment: "Sidebar: the user’s main Proton Drive volume")
        ),
        photos: DriveRoot(
            shareID: "share-photos", rootLinkID: "link-photos-root",
            volumeID: "vol-photos", kind: .photos,
            displayName: String(localized: "Photos", comment: "Sidebar: the Proton Drive Photos volume")
        ),
        computers: [
            DriveRoot(
                shareID: "share-macbook", rootLinkID: "link-macbook-root",
                volumeID: "vol-macbook", kind: .device, displayName: "Computer 1"
            )
        ]
    )

    /// Folder linkID → children. Unknown and empty folders default to [].
    private let tree: [String: [DriveItem]]

    init() {
        let main = "share-main", mainRoot = "link-main-root"
        let mac = "share-macbook", macRoot = "link-macbook-root"
        tree = [
            mainRoot: [
                demoFolder("demo-projects", "Projects", in: mainRoot, share: main, days: 0),
                demoFolder("demo-empty", "Empty Folder", in: mainRoot, share: main, days: 1),
                demoFolder(Self.brokenFolderID, "Broken Folder", in: mainRoot, share: main, days: 2),
                demoFolder("demo-unicode", "ação ✓ unicode", in: mainRoot, share: main, days: 3),
                demoFile("demo-long-name", demoLongFileName, in: mainRoot, share: main,
                         size: 12_480, days: 4, mime: "text/plain"),
                demoFile("demo-file-01", "IMG_4021.jpg", in: mainRoot, share: main,
                         size: 4_812_300, days: 5, mime: "image/jpeg"),
                demoFile("demo-file-02", "screenshot-2026-08.png", in: mainRoot, share: main,
                         size: 1_920_445, days: 6, mime: "image/png"),
                demoFile("demo-file-03", "keynote-draft.mov", in: mainRoot, share: main,
                         size: 822_114_050, days: 7, mime: "video/quicktime"),
                demoFile("demo-file-04", "backup-2026.zip", in: mainRoot, share: main,
                         size: 1_204_002_211, days: 8, mime: "application/zip"),
                demoFile("demo-file-05", "release-notes.md", in: mainRoot, share: main,
                         size: 8_412, days: 9, mime: "text/markdown"),
                demoFile("demo-file-06", "config.json", in: mainRoot, share: main,
                         size: 2_048, days: 10, mime: "application/json"),
                demoFile("demo-file-07", "DriveClient.swift", in: mainRoot, share: main,
                         size: 15_330, days: 11, mime: "text/x-swift"),
                demoFile("demo-file-08", "private.key", in: mainRoot, share: main,
                         size: 3_400, days: 12, mime: "application/pgp-keys"),
                demoFile("demo-file-09", "Budget.numbers", in: mainRoot, share: main,
                         size: 402_100, days: 13, mime: "application/vnd.apple.numbers"),
                demoFile("demo-file-10", "Invoice March.pdf", in: mainRoot, share: main,
                         size: 241_172, days: 14, mime: "application/pdf"),
                demoFile("demo-file-11", "voice-memo.m4a", in: mainRoot, share: main,
                         size: 5_120_700, days: 15, mime: "audio/mp4"),
                demoFile("demo-file-12", "archive.tar.gz", in: mainRoot, share: main,
                         size: 96_400_000, days: 16, mime: "application/gzip"),
                demoFile("demo-file-13", "logo.svg", in: mainRoot, share: main,
                         size: 18_220, days: 17, mime: "image/svg+xml"),
                demoFile("demo-file-14", "todo.txt", in: mainRoot, share: main,
                         size: 1_024, days: 18, mime: "text/plain"),
                demoFile("demo-file-15", "data.csv", in: mainRoot, share: main,
                         size: 65_536, days: 19, mime: "text/csv"),
                demoFile("demo-file-16", "index.html", in: mainRoot, share: main,
                         size: 9_728, days: 20, mime: "text/html"),
                demoFile("demo-file-17", "reading.epub", in: mainRoot, share: main,
                         size: 1_400_500, days: 21, mime: "application/epub+zip"),
                demoFile("demo-file-18", "Vacation.webp", in: mainRoot, share: main,
                         size: 3_310_080, days: 22, mime: "image/webp"),
                demoFile("demo-file-19", "report.docx", in: mainRoot, share: main,
                         size: 87_040, days: 23, mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                demoFile("demo-file-20", "installer.dmg", in: mainRoot, share: main,
                         size: 210_763_776, days: 24, mime: "application/x-apple-diskimage"),
                demoFile("demo-encrypted", "Encrypted Item", in: mainRoot, share: main,
                         size: 51_200, days: 25, mime: nil, decrypted: false),
            ],
            "demo-projects": [
                demoFolder("demo-client-a", "Client A", in: "demo-projects", share: main, days: 0),
                demoFolder("demo-client-b", "Client B", in: "demo-projects", share: main, days: 1),
            ],
            "demo-client-a": [
                demoFolder("demo-drafts", "Drafts", in: "demo-client-a", share: main, days: 0),
                demoFile("demo-contract", "contract.pdf", in: "demo-client-a", share: main,
                         size: 241_172, days: 1, mime: "application/pdf"),
            ],
            "demo-drafts": [
                demoFile("demo-draft-1", "Draft v1.docx", in: "demo-drafts", share: main,
                         size: 45_056, days: 0, mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                demoFile("demo-draft-2", "Draft v2.docx", in: "demo-drafts", share: main,
                         size: 47_616, days: 1, mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                demoFile("demo-draft-3", "Draft summary.pdf", in: "demo-drafts", share: main,
                         size: 118_784, days: 2, mime: "application/pdf"),
            ],
            "demo-client-b": [],
            "demo-empty": [],
            "demo-unicode": [
                demoFile("demo-unicode-file", "relatório ✓ final.pdf", in: "demo-unicode",
                         share: main, size: 88_900, days: 0, mime: "application/pdf"),
            ],
            "link-photos-root": [],
            macRoot: [
                demoFolder("demo-mac-backups", "Backups", in: macRoot, share: mac, days: 0),
                demoFolder("demo-mac-screenshots", "Screenshots", in: macRoot, share: mac, days: 1),
                demoFile("demo-mac-file-1", "photo-dump.zip", in: macRoot, share: mac,
                         size: 1_204_002_211, days: 2, mime: "application/zip"),
                demoFile("demo-mac-file-2", "notes.md", in: macRoot, share: mac,
                         size: 8_412, days: 3, mime: "text/markdown"),
                demoFile("demo-mac-file-3", "machine-config.json", in: macRoot, share: mac,
                         size: 2_048, days: 4, mime: "application/json"),
            ],
        ]
    }

    func roots() async throws -> DriveRoots {
        // `try?`: a cancelled load still returns the fixture — the demo has
        // no real request to abort.
        try? await Task.sleep(for: Self.latency)
        return demoRoots
    }

    func children(of location: DriveLocation) async throws -> [DriveItem] {
        try? await Task.sleep(for: Self.latency)
        if location.linkID == Self.brokenFolderID {
            throw ProtonAPIError.transport(URLError(.networkConnectionLost))
        }
        return tree[location.linkID] ?? []
    }
}
#endif
