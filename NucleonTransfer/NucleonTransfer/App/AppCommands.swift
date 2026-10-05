// Nucleon Transfer — menu bar commands (F7 S4.2).
// One menu bar, one window: browser commands reach the focused scene's
// BrowserModel via @FocusedValue. App-level commands (Sign Out, Show
// Transfers) take the app's single AppSession by parameter, so they keep
// working while the Settings window is key (a focused value is nil
// there — live audit). "Sign Out…" brings the main window forward and
// lands on the sidebar footer's confirmationDialog, including the
// active-transfers warning. Every item disables itself when it doesn't
// apply: no browser, empty selection, read-only root, signed out.
import AppKit
import SwiftUI

extension FocusedValues {
    /// The BrowserModel of the focused browser scene (nil while signed
    /// out or when no drive root is on screen).
    @Entry var browserModel: BrowserModel?
    /// The browser's filter field has keyboard focus (F8.4-U3) — Move to
    /// Trash steps aside so ⌘⌫ deletes to line start in the field.
    @Entry var browserSearchFocused: Bool?
}

struct AppCommands: Commands {
    @FocusedValue(\.browserModel) private var focusedBrowser
    @FocusedValue(\.browserSearchFocused) private var searchFocused
    @AppStorage(BrowserPreferences.showPathBarKey) private var showPathBar = false
    /// The app's one session (NucleonTransferApp) — not a focused value,
    /// which goes nil while the Settings window is key.
    let session: AppSession
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        // App menu — custom About with the 6.6 disclaimer in the credits.
        CommandGroup(replacing: .appInfo) {
            Button("About Nucleon Transfer") {
                NSApp.orderFrontStandardAboutPanel(options: [
                    // CFBundleName is the target name ("NucleonTransfer").
                    .applicationName: AboutContent.appName,
                    .credits: AboutContent.panelCredits,
                ])
            }
        }

        // File menu — folder creation + upload intake (S3.1 panels).
        CommandGroup(replacing: .newItem) {
            Button("New Folder") {
                browser?.showingNewFolder = true
            }
            .keyboardShortcut("n", modifiers: [.command, .shift])
            .disabled(!canWrite)

            // F8.4-U1: disabled (with the reason) once Proton refused an
            // upload with code 2000 this run.
            Button("Upload Files…") {
                Task { await browser?.uploadPanel(folders: false) }
            }
            .keyboardShortcut("u", modifiers: [.command])
            .disabled(!canUpload)
            .help(uploadHelp)

            Button("Upload Folder…") {
                Task { await browser?.uploadPanel(folders: true) }
            }
            .keyboardShortcut("u", modifiers: [.command, .shift])
            .disabled(!canUpload)
            .help(uploadHelp)
        }

        // Go menu — Finder-style navigation: ⌘[ / ⌘] back/forward (F8.4-U3),
        // ⌘↑ up, ⌘↓ open, ⌘R reload.
        CommandMenu("Go") {
            Button("Back") {
                browser?.goBack()
            }
            .keyboardShortcut("[", modifiers: [.command])
            .disabled(!(browser?.canGoBack ?? false))

            Button("Forward") {
                browser?.goForward()
            }
            .keyboardShortcut("]", modifiers: [.command])
            .disabled(!(browser?.canGoForward ?? false))

            Divider()

            Button("Enclosing Folder") {
                browser?.goToParent()
            }
            .keyboardShortcut(.upArrow, modifiers: [.command])
            .disabled(browser?.path.isEmpty ?? true)

            Button("Open") {
                guard let browser else { return }
                browser.openSelection(browser.selection)
            }
            .keyboardShortcut(.downArrow, modifiers: [.command])
            .disabled(browser?.selection.isEmpty ?? true)

            Divider()

            Button("Reload") {
                Task { await browser?.reloadCurrent() }
            }
            .keyboardShortcut("r", modifiers: [.command])
            .disabled(browser == nil || isReloading)
        }

        // Edit-menu-adjacent item actions (after the pasteboard group).
        // ⌘⌫ is the Finder trash shortcut; ⌥⌘D avoids the ⌘D collision
        // with Finder's Add to Sidebar/bookmark conventions.
        CommandGroup(after: .pasteboard) {
            Button("Move to Trash") {
                guard let browser else { return }
                browser.requestTrash(browser.selection)
            }
            .keyboardShortcut(.delete, modifiers: [.command])
            .disabled(!canTrash)

            Button("Download…") {
                guard let browser else { return }
                browser.downloadItems(browser.selection)
            }
            .keyboardShortcut("d", modifiers: [.command, .option])
            .disabled(browser?.selection.isEmpty ?? true)
        }

        // View menu — the transfers popover bound on the activity store.
        CommandGroup(after: .toolbar) {
            // The popover anchors to the toolbar button inside FolderView,
            // so it needs a live browser — not just a signed-in session.
            Button("Show Transfers") {
                session.activity.presentTransfers = true
            }
            .keyboardShortcut("t", modifiers: [.command, .option])
            .disabled(session.phase != .signedIn || browser == nil)

            // F8.4-U3: Finder's path bar, persisted in @AppStorage.
            Button(showPathBar ? "Hide Path Bar" : "Show Path Bar") {
                showPathBar.toggle()
            }
            .keyboardShortcut("p", modifiers: [.command, .option])
            .disabled(browser == nil)
        }

        // App menu, after Settings… — same confirm flow as the account
        // footer while the shell (and so the footer) is up; other states
        // (2FA prompt, root load error) sign out directly so the menu item
        // never dead-ends.
        CommandGroup(after: .appSettings) {
            Button("Sign Out…") {
                if session.phase == .signedIn, session.roots != nil {
                    openWindow(id: "main")
                    session.signOutRequested = true
                } else {
                    Task { await session.signOut() }
                }
            }
            .disabled(!canSignOut)
        }

        // Help menu (F8.4-U7) — replaces the default "Nucleon Transfer
        // Help" item (there is no Help Book); every item opens the GitHub
        // repository in the browser.
        CommandGroup(replacing: .help) {
            Button("Nucleon Transfer Help") { open(HelpLinks.readme) }
            Button("Known Limitations") { open(HelpLinks.knownLimitations) }
            Divider()
            Button("Report an Issue…") { open(HelpLinks.newIssue) }
            Button("Privacy & Security") { open(HelpLinks.security) }
        }
    }

    /// The focused browser, or nil while one of its sheets/dialogs/alerts
    /// is up — every browser command then disables itself instead of
    /// queueing a request behind the modal.
    private var browser: BrowserModel? {
        guard let focusedBrowser, !focusedBrowser.isPresentingModal else { return nil }
        return focusedBrowser
    }

    /// Opens a help link in the default browser (no-op on a nil URL).
    private func open(_ url: URL?) {
        guard let url else { return }
        NSWorkspace.shared.open(url)
    }

    /// Write-capable root on screen (not Photos, not signed out).
    private var canWrite: Bool {
        browser?.root.allowsWrites == true
    }

    /// Writable root and uploads not blocked by Proton (F8.4-U1).
    private var canUpload: Bool {
        browser?.canUpload == true
    }

    /// Menu-item tooltip: the blocked reason, else nothing.
    private var uploadHelp: Text {
        browser?.uploadsBlocked == true ? Text(UploadsBlockedCopy.message) : Text(verbatim: "")
    }

    /// Trash needs a writable root AND a non-empty selection — and the
    /// filter field must not have focus, or ⌘⌫ would trash rows instead of
    /// deleting to the start of the line (F8.4-U3).
    private var canTrash: Bool {
        canWrite && !(browser?.selection.isEmpty ?? true) && searchFocused != true
    }

    /// Mirror of the toolbar Reload button's busy state.
    private var isReloading: Bool {
        guard let browser else { return false }
        return browser.state(for: browser.current).phase == .loading
    }

    /// Signed in, or parked on the 2FA prompt (Sign Out doubles as the
    /// cancel path there). Disabled mid-signIn/unlock and while a 2FA code
    /// is being verified — the in-flight work must finish or fail on its own.
    private var canSignOut: Bool {
        if session.phase == .signedIn { return true }
        return session.phase == .needsTwoFactor && !session.isVerifyingTwoFactor
    }
}
