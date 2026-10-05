// Nucleon Transfer — F8.4-U7 settings (Swift Testing).
// AppSettings readers (defaults for absent keys, clamping, the inverted
// trash-suppression flag), the default-download-folder decision with an
// injected LocalFileAccess (FakeFS), the panel message and help links.
import Foundation
import Testing

@testable import NucleonTransfer

/// A throwaway UserDefaults suite per test.
private func makeDefaults() -> UserDefaults {
    let name = "nt.tests.settings.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: name) ?? .standard
    defaults.removePersistentDomain(forName: name)
    return defaults
}

struct AppSettingsTests {
    @Test func absentKeysUseDocumentedDefaults() {
        let defaults = makeDefaults()
        #expect(AppSettings.maxConcurrentUploads(defaults) == 4)
        #expect(AppSettings.maxConcurrentDownloads(defaults) == 4)
        #expect(AppSettings.asksDownloadDestination(defaults))
        #expect(AppSettings.opensTransfersOnStart(defaults))
        #expect(AppSettings.confirmsTrash(defaults))
        #expect(AppSettings.downloadFolderBookmark(defaults) == nil)
    }

    @Test func storedValuesWinAndConcurrencyIsClamped() {
        let defaults = makeDefaults()
        defaults.set(false, forKey: AppSettings.askDownloadDestinationKey)
        defaults.set(false, forKey: AppSettings.opensTransfersOnStartKey)
        defaults.set(true, forKey: AppSettings.suppressTrashConfirmationKey)
        defaults.set(2, forKey: AppSettings.maxConcurrentDownloadsKey)
        defaults.set(99, forKey: AppSettings.maxConcurrentUploadsKey)
        #expect(!AppSettings.asksDownloadDestination(defaults))
        #expect(!AppSettings.opensTransfersOnStart(defaults))
        #expect(!AppSettings.confirmsTrash(defaults))
        #expect(AppSettings.maxConcurrentDownloads(defaults) == 2)
        #expect(AppSettings.maxConcurrentUploads(defaults) == 8)
        defaults.set(-3, forKey: AppSettings.maxConcurrentDownloadsKey)
        #expect(AppSettings.maxConcurrentDownloads(defaults) == 4)
    }

    @Test func downloadFolderSetAndClear() {
        let defaults = makeDefaults()
        AppSettings.setDownloadFolder(bookmark: Data("bm".utf8), path: "/Users/me/Downloads", in: defaults)
        #expect(AppSettings.downloadFolderBookmark(defaults) == Data("bm".utf8))
        #expect(defaults.string(forKey: AppSettings.downloadFolderPathKey) == "/Users/me/Downloads")
        AppSettings.clearDownloadFolder(in: defaults)
        #expect(AppSettings.downloadFolderBookmark(defaults) == nil)
        #expect(defaults.string(forKey: AppSettings.downloadFolderPathKey) == nil)
    }

    @Test func helpLinksPointAtTheRepository() throws {
        let links = [HelpLinks.readme, HelpLinks.knownLimitations, HelpLinks.newIssue, HelpLinks.security]
        for link in links {
            let url = try #require(link)
            #expect(url.scheme == "https")
            #expect(url.absoluteString.hasPrefix("https://github.com/errrepe/Nucleon-Transfer"))
        }
        #expect(HelpLinks.knownLimitations?.fragment == "known-limitations-alpha")
    }
}

struct DownloadFolderPreferenceTests {
    @Test func askEveryTimeAlwaysAsks() {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        let decision = DownloadFolderPreference.decide(askEveryTime: true, bookmark: Data("bm".utf8), access: fs.access)
        #expect(decision == .ask)
        #expect(fs.started.isEmpty)
    }

    @Test func noBookmarkAsks() {
        let fs = FakeFS()
        #expect(DownloadFolderPreference.decide(askEveryTime: false, bookmark: nil, access: fs.access) == .ask)
    }

    @Test func resolvableBookmarkUsesFolderAndBalancesScope() {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        let decision = DownloadFolderPreference.decide(askEveryTime: false, bookmark: Data("bm".utf8), access: fs.access)
        #expect(decision == .folder(fs.resolved, refreshedBookmark: nil))
        #expect(fs.started == [fs.resolved])
        #expect(fs.stopped == [fs.resolved])
    }

    @Test func unresolvableBookmarkFallsBackToAsk() {
        let fs = FakeFS()
        fs.resolveFails = true
        #expect(DownloadFolderPreference.decide(askEveryTime: false, bookmark: Data("bm".utf8), access: fs.access) == .ask)
    }

    @Test func missingFolderFallsBackToAskAndStopsScope() {
        let fs = FakeFS()
        let decision = DownloadFolderPreference.decide(askEveryTime: false, bookmark: Data("bm".utf8), access: fs.access)
        #expect(decision == .ask)
        #expect(fs.stopped == fs.started)
    }

    @Test func staleBookmarkIsRefreshedAndPersisted() {
        let fs = FakeFS()
        fs.existing = [fs.resolved.path]
        fs.stale = true
        let defaults = makeDefaults()
        defaults.set(false, forKey: AppSettings.askDownloadDestinationKey)
        AppSettings.setDownloadFolder(bookmark: Data("old".utf8), path: "/old", in: defaults)
        let decision = DownloadFolderPreference.decide(defaults: defaults, access: fs.access)
        let fresh = Data("fresh:\(fs.resolved.path)".utf8)
        #expect(decision == .folder(fs.resolved, refreshedBookmark: fresh))
        #expect(AppSettings.downloadFolderBookmark(defaults) == fresh)
        #expect(defaults.string(forKey: AppSettings.downloadFolderPathKey) == fs.resolved.path)
    }

    @Test func panelMessageNamesTheBatchSize() {
        #expect(DownloadFolderPreference.panelMessage(itemCount: 3) == "Choose where to save 3 items.")
        #expect(DownloadFolderPreference.panelMessage(itemCount: 1) == "Choose where to save 1 item.")
        #expect(DownloadFolderPreference.panelMessage(itemCount: nil) == "Choose where to save the download.")
    }
}
