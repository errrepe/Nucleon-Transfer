// Nucleon Transfer — menu bar commands (F7 S4.2).
// One menu bar, one window: commands reach the focused scene's state via
// @FocusedValue — FolderView publishes its BrowserModel, RootView the
// AppSession, and StorageFooterView its sign-out request (so the menu's
// "Sign Out…" lands on the same confirmationDialog, including the
// active-transfers warning). Every item disables itself when it doesn't
// apply: no browser, empty selection, read-only root, signed out.
import AppKit
import SwiftUI

/// Sign-out request value: the sidebar footer's `beginSignOut` closure.
/// Declared as a FocusedValueKey (not @Entry) — @Entry warns about
/// storing closures, which aren't comparable.
private struct RequestSignOutFocusedKey: FocusedValueKey {
    typealias Value = @MainActor () -> Void
}

extension FocusedValues {
    /// The BrowserModel of the focused browser scene (nil while signed
    /// out or when no drive root is on screen).
    @Entry var browserModel: BrowserModel?
    /// The AppSession of the focused scene — for app-level commands
    /// (Show Transfers, Sign Out) that outlive any single browser.
    @Entry var appSession: AppSession?
    /// Sign-out request published by the sidebar account footer — it
    /// runs the footer's `beginSignOut` (active-transfers check, then
    /// the confirmationDialog) so the menu path keeps the same UX.
    var requestSignOut: (@MainActor () -> Void)? {
        get { self[RequestSignOutFocusedKey.self] }
        set { self[RequestSignOutFocusedKey.self] = newValue }
    }
}

struct AppCommands: Commands {
    @FocusedValue(\.browserModel) private var browser
    @FocusedValue(\.appSession) private var session
    @FocusedValue(\.requestSignOut) private var requestSignOut

    var body: some Commands {
        // App menu — custom About with the 6.6 disclaimer in the credits.
        CommandGroup(replacing: .appInfo) {
            Button("About Nucleon Transfer") {
                NSApp.orderFrontStandardAboutPanel(options: [
                    .credits: NSAttributedString(string: AboutContent.disclaimer)
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

            Button("Upload Files…") {
                Task { await browser?.uploadPanel(folders: false) }
            }
            .keyboardShortcut("u", modifiers: [.command])
            .disabled(!canWrite)

            Button("Upload Folder…") {
                Task { await browser?.uploadPanel(folders: true) }
            }
            .keyboardShortcut("u", modifiers: [.command, .shift])
            .disabled(!canWrite)
        }

        // Go menu — Finder-style navigation: ⌘↑ up, ⌘↓ open, ⌘R reload.
        CommandMenu("Go") {
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
                session?.activity.presentTransfers = true
            }
            .keyboardShortcut("t", modifiers: [.command, .option])
            .disabled(session?.phase != .signedIn || browser == nil)
        }

        // App menu, after Settings… — same confirm flow as the account
        // footer (its closure is published while the shell is on screen);
        // signed-in-but-no-footer states (root load error) fall back to a
        // direct sign-out so the menu item never dead-ends.
        CommandGroup(after: .appSettings) {
            Button("Sign Out…") {
                if let requestSignOut {
                    requestSignOut()
                } else if let session {
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

    /// Opens a help link in the default browser (no-op on a nil URL).
    private func open(_ url: URL?) {
        guard let url else { return }
        NSWorkspace.shared.open(url)
    }

    /// Write-capable root on screen (not Photos, not signed out).
    private var canWrite: Bool {
        browser?.root.allowsWrites == true
    }

    /// Trash needs a writable root AND a non-empty selection.
    private var canTrash: Bool {
        canWrite && !(browser?.selection.isEmpty ?? true)
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
        guard let session else { return false }
        if session.phase == .signedIn { return true }
        return session.phase == .needsTwoFactor && !session.isVerifyingTwoFactor
    }
}
