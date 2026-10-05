// Nucleon Transfer — Settings scene (F7 S4.2; F8.4-U7), opened with ⌘,.
// General: open Transfers on start, ask before moving to Trash.
// Transfers: default download folder (security-scoped bookmark, "Ask every
// time" on by default) and the simultaneous uploads/downloads caps. The
// uploads cap is applied to the TransferQueue on change (the app scene's
// launch .task applies the stored value; SettingsView only exists on
// demand). Keys + defaults live in Core's AppSettings.
// About: icon, name, version + build, the 6.6 disclaimer, source link.
// U7 layout: no fixed frame (clipped at larger text sizes) — each grouped
// Form sizes itself vertically; only a minimum width is set.
import AppKit
import SwiftUI

/// About-panel copy (spec 6.6) — shared by the App menu's About command
/// (shown in the standard panel's credits) and the Settings › About tab.
enum AboutContent {
    static let disclaimer = "Nucleon Transfer is an independent, open-source app. It is not affiliated with or endorsed by Proton AG. Your password is used only to sign in and unlock your keys on this Mac — it is never stored."
    static let sourceCodeURL = URL(string: "https://github.com/errrepe/Nucleon-Transfer")
}

struct SettingsView: View {
    @AppStorage(AppSettings.maxConcurrentUploadsKey)
    private var maxConcurrentUploads = AppSettings.defaultMaxConcurrentUploads
    @AppStorage(AppSettings.maxConcurrentDownloadsKey)
    private var maxConcurrentDownloads = AppSettings.defaultMaxConcurrentDownloads
    @AppStorage(AppSettings.askDownloadDestinationKey)
    private var askDownloadDestination = AppSettings.defaultAskDownloadDestination
    @AppStorage(AppSettings.downloadFolderPathKey)
    private var downloadFolderPath = ""
    @AppStorage(AppSettings.opensTransfersOnStartKey)
    private var opensTransfersOnStart = AppSettings.defaultOpensTransfersOnStart
    @AppStorage(AppSettings.suppressTrashConfirmationKey)
    private var suppressTrashConfirmation = AppSettings.defaultSuppressTrashConfirmation
    @Environment(AppSession.self) private var session
    /// Last "Choose…" failure (bookmark couldn't be created); nil = none.
    @State private var folderError: String?

    var body: some View {
        TabView {
            generalTab
                .tabItem { Label("General", systemImage: "gear") }
            transfersTab
                .tabItem { Label("Transfers", systemImage: "arrow.up.arrow.down") }
            aboutTab
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(minWidth: 460)
    }

    private var generalTab: some View {
        Form {
            Toggle("Open Transfers when a transfer starts", isOn: $opensTransfersOnStart)
            Toggle("Ask before moving to Trash", isOn: Binding(
                get: { !suppressTrashConfirmation },
                set: { suppressTrashConfirmation = !$0 }
            ))
        }
        .settingsFormLayout()
    }

    private var transfersTab: some View {
        Form {
            Section("Downloads") {
                Toggle("Ask where to save every time", isOn: $askDownloadDestination)
                LabeledContent("Default folder") {
                    HStack {
                        Text(folderDisplayName)
                            .foregroundStyle(downloadFolderPath.isEmpty ? .secondary : .primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(downloadFolderPath)
                        Button("Choose…") {
                            Task { await chooseDownloadFolder() }
                        }
                    }
                }
                .disabled(askDownloadDestination)
                if let folderError {
                    Label(folderError, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            Section("Simultaneous Transfers") {
                Stepper(
                    "Uploads: \(maxConcurrentUploads)",
                    value: $maxConcurrentUploads,
                    in: AppSettings.concurrencyRange
                )
                .monospacedDigit()
                Stepper(
                    "Downloads: \(maxConcurrentDownloads)",
                    value: $maxConcurrentDownloads,
                    in: AppSettings.concurrencyRange
                )
                .monospacedDigit()
            }
        }
        .settingsFormLayout()
        .onChange(of: maxConcurrentUploads) { _, newValue in
            Task { await session.queue.setMaxConcurrent(newValue) }
        }
    }

    /// Folder name for the row (full path in the tooltip); "None" until
    /// a folder is chosen.
    private var folderDisplayName: String {
        downloadFolderPath.isEmpty
            ? String(localized: "None")
            : FileManager.default.displayName(atPath: downloadFolderPath)
    }

    /// Panel → security-scoped bookmark (app scope) → defaults. The panel
    /// URL's grant is released once the bookmark exists; downloads
    /// re-acquire it from the bookmark.
    private func chooseDownloadFolder() async {
        guard let url = await Panels.chooseDefaultDownloadFolder() else { return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let bookmark = try LocalFileAccess.live.makeBookmark(url)
            AppSettings.setDownloadFolder(bookmark: bookmark, path: url.path, in: .standard)
            folderError = nil
        } catch {
            folderError = String(localized: "Couldn’t remember this folder. Choose another one.")
        }
    }

    private var aboutTab: some View {
        VStack(spacing: 10) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 64, height: 64)
                .accessibilityHidden(true)
            Text("Nucleon Transfer")
                .font(.title3)
                .bold()
            Text("Version \(versionString)")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(AboutContent.disclaimer)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 340)
            if let url = AboutContent.sourceCodeURL {
                Link("Source Code", destination: url)
            }
            Text("MIT License")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding()
    }

    /// "0.1.0 (4)" — marketing version plus build number; degrades to
    /// whichever Info.plist value is present (preview hosts included).
    private var versionString: String {
        let version = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String
        let build = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String
        switch (version, build) {
        case let (version?, build?): return "\(version) (\(build))"
        case let (version?, nil): return version
        case let (nil, build?): return build
        case (nil, nil): return "—"
        }
    }
}

private extension View {
    /// Grouped Form that takes its natural height (no inner scrolling,
    /// no extra padding — the grouped style already insets).
    func settingsFormLayout() -> some View {
        formStyle(.grouped)
            .scrollDisabled(true)
            .fixedSize(horizontal: false, vertical: true)
    }
}

#if DEBUG
#Preview("Settings") {
    SettingsView()
        .environment(PreviewFixtures.session())
}
#endif
