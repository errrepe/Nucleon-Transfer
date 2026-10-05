// Nucleon Transfer — shared NSOpenPanel presenters (F7 S2.3; F8.4-U7).
// Single home for the app's file/folder pickers so browser, transfers and
// future upload flows share ONE non-blocking pattern: sheet on the key
// window, app-modal fallback when there is no key window, never a nested
// runModal loop — the MainActor stays free while the panel is up (the
// sample /tmp/nt-sample.txt hang came from runModal on a non-key app).
// Outcomes resolve through PanelIntake (pure, unit-tested): nil/empty =
// cancelled/dismissed, callers never proceed.
// U7: `prompt` is the OK button's title — keep it short ("Download
// Here"); the explanation goes in `message`. `downloadDestination` honours
// the Settings default folder before falling back to the panel.
import AppKit
import Foundation

@MainActor
enum Panels {
    /// Download destination for a batch of `itemCount` items: the default
    /// folder from Settings when "Ask every time" is off and its bookmark
    /// resolves, otherwise the destination panel. Either way the caller
    /// starts and balances security-scoped access on the returned URL.
    static func downloadDestination(itemCount: Int) async -> URL? {
        switch DownloadFolderPreference.decide(defaults: .standard, access: .live) {
        case let .folder(url, _):
            return url
        case .ask:
            return await chooseDownloadFolder(itemCount: itemCount)
        }
    }

    /// Download destination picker: directories only, single selection.
    /// Returns the chosen directory on OK, nil on cancel/dismiss — the
    /// caller reports a cancelled status and never proceeds. URLs from
    /// NSOpenPanel arrive with security-scoped access already started;
    /// the CALLER owns the matching stopAccessingSecurityScopedResource.
    /// `itemCount` nil keeps the pre-U7 call sites compiling (generic
    /// message).
    static func chooseDownloadFolder(itemCount: Int? = nil) async -> URL? {
        await chooseFolder(
            prompt: String(localized: "Download Here"),
            message: DownloadFolderPreference.panelMessage(itemCount: itemCount)
        )
    }

    /// Settings › Transfers "Choose…": picks the default download folder.
    /// Same panel shape as the download picker, Settings-specific copy.
    static func chooseDefaultDownloadFolder() async -> URL? {
        await chooseFolder(
            prompt: String(localized: "Choose"),
            message: String(localized: "Choose the folder where downloads are saved.")
        )
    }

    private static func chooseFolder(prompt: String, message: String) async -> URL? {
        await withCheckedContinuation { cont in
            let panel = NSOpenPanel()
            panel.canChooseFiles = false
            panel.canChooseDirectories = true
            panel.canCreateDirectories = true
            panel.allowsMultipleSelection = false
            panel.prompt = prompt
            panel.message = message
            let completion: (NSApplication.ModalResponse) -> Void = { response in
                cont.resume(returning: PanelIntake.downloadDestination(
                    responseOK: response == .OK, url: panel.url
                ))
            }
            if let window = NSApp.keyWindow {
                panel.beginSheetModal(for: window, completionHandler: completion)
            } else {
                panel.begin(completionHandler: completion)
            }
        }
    }

    /// Upload intake picker (S3.1): `folders: false` = files only,
    /// `folders: true` = folders only — both multi-selection. Returns the
    /// confirmed URLs, or [] on cancel/dismiss (a no-op for the caller).
    /// The returned URLs carry security-scoped access already started;
    /// the caller decides how long to hold the grant.
    static func chooseUploadItems(folders: Bool) async -> [URL] {
        await withCheckedContinuation { cont in
            let panel = NSOpenPanel()
            panel.canChooseFiles = !folders
            panel.canChooseDirectories = folders
            panel.allowsMultipleSelection = true
            panel.canCreateDirectories = false
            panel.prompt = String(localized: "Upload", comment: "Upload panel OK button")
            let completion: (NSApplication.ModalResponse) -> Void = { response in
                cont.resume(returning: PanelIntake.uploadURLs(
                    responseOK: response == .OK, urls: panel.urls
                ))
            }
            if let window = NSApp.keyWindow {
                panel.beginSheetModal(for: window, completionHandler: completion)
            } else {
                panel.begin(completionHandler: completion)
            }
        }
    }
}
