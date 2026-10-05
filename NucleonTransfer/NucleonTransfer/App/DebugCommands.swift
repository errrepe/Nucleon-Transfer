// Nucleon Transfer — DEBUG-only "Debug" menu (F8.5-V3).
// Compiled out of release builds with `#if DEBUG`, like the demo mode and
// its sidebar badge. "Check Saved Sign-In" inspects the two "Keep me
// signed in" Keychain items with an attributes-only query (never
// kSecReturnData, no Touch ID UI) and shows exists / accessibility /
// synchronizable / access control in an alert. No secret is read,
// displayed or logged. Titles are verbatim (not in the String Catalog —
// developer-only UI).
import AppKit
import SwiftUI

struct DebugCommands: Commands {
    var body: some Commands {
        #if DEBUG
        CommandMenu(Self.menuTitle) {
            Button(Self.checkTitle) {
                Self.showSavedSignInCheck()
            }
            // Flips the app into the "Proton refused uploads (2000)" state
            // without a network round-trip — reproduces that UI change in
            // Demo Mode.
            Button("Simulate Uploads Blocked") {
                DebugOverrides.shared.uploadsBlocked.toggle()
            }
        }
        #else
        EmptyCommands()
        #endif
    }
}

#if DEBUG
/// Runtime switches for the Debug menu (DEBUG builds only).
@MainActor @Observable
final class DebugOverrides {
    static let shared = DebugOverrides()
    var uploadsBlocked = false
}

extension DebugCommands {
    private static let menuTitle = "Debug"
    private static let checkTitle = "Check Saved Sign-In"

    @MainActor
    private static func showSavedSignInCheck() {
        let store = LiveKeychainStore()
        let session = store.inspect(account: SessionVault.account)
        let kek = store.inspect(account: SessionVault.kekAccount)
        let alert = NSAlert()
        alert.messageText = checkTitle
        alert.informativeText = """
        Session item (\(SessionVault.account)):
        \(session.summary)

        Touch ID key item (\(SessionVault.kekAccount)):
        \(kek.summary)
        """
        alert.runModal()
    }
}
#endif
