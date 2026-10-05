// Nucleon Transfer — persisted user settings: keys, defaults, readers (F7
// S4.2; F8.4-U7).
// Single home for every UserDefaults key the Settings window writes
// (through @AppStorage) and the app reads outside SwiftUI (launch apply,
// coordinators). The readers take the UserDefaults instance so tests use a
// private suite; absent keys fall back to the SAME defaults the
// @AppStorage declarations use, so the UI and the readers never disagree.
import Foundation

enum AppSettings {
    /// Shared bounds of both concurrency steppers.
    static let concurrencyRange = 1...8

    // MARK: Uploads

    static let maxConcurrentUploadsKey = "maxConcurrentUploads"
    static let defaultMaxConcurrentUploads = 4

    // MARK: Downloads

    static let maxConcurrentDownloadsKey = "maxConcurrentDownloads"
    static let defaultMaxConcurrentDownloads = 4

    /// "Ask every time" — show the destination panel for each download
    /// (default on). Off + a resolvable bookmark = save straight there.
    static let askDownloadDestinationKey = "askDownloadDestination"
    static let defaultAskDownloadDestination = true

    /// Security-scoped bookmark (app scope) of the default download folder.
    static let downloadFolderBookmarkKey = "downloadFolderBookmark"
    /// Display-only path of the bookmarked folder (Settings label); the
    /// bookmark, never this path, is what grants sandbox access.
    static let downloadFolderPathKey = "downloadFolderPath"

    // MARK: General

    /// Open the Transfers popover when a transfer starts (default on).
    static let opensTransfersOnStartKey = "opensTransfersOnStart"
    static let defaultOpensTransfersOnStart = true

    /// True = the user ticked "Don't ask again" on the trash confirmation
    /// (`.dialogSuppressionToggle`) or turned "Ask before moving to Trash"
    /// off. Stored as the suppression flag so the dialog binds directly.
    static let suppressTrashConfirmationKey = "suppressTrashConfirmation"
    static let defaultSuppressTrashConfirmation = false

    // MARK: Sign-in (F8.5)

    /// "Keep me signed in" on the login screen (default OFF). On = the next
    /// successful sign-in stores a remembered session in the Keychain;
    /// off = nothing is stored and any existing item is deleted.
    static let keepSignedInKey = "keepSignedIn"
    static let defaultKeepSignedIn = false

    /// Last username that signed in successfully — prefills the login
    /// field. Not a secret, but only kept with "Keep me signed in" (F8.5
    /// review): stored at a sign-in with it on, cleared at a sign-in with
    /// it off and at a sign-out while it is off, and by "Forget This Mac".
    static let lastUsernameKey = "lastUsername"

    /// "Require Touch ID" (Settings › Account, default OFF; F8.5-V3). On =
    /// the remembered session is sealed under a Touch ID protected key.
    /// Only meaningful while "Keep me signed in" is on.
    static let requireTouchIDKey = "requireTouchID"
    static let defaultRequireTouchID = false

    // MARK: Readers

    static func keepsSignedIn(_ defaults: UserDefaults) -> Bool {
        bool(defaults, keepSignedInKey, fallback: defaultKeepSignedIn)
    }

    static func lastUsername(_ defaults: UserDefaults) -> String? {
        guard let name = defaults.string(forKey: lastUsernameKey), !name.isEmpty else { return nil }
        return name
    }

    static func requiresTouchID(_ defaults: UserDefaults) -> Bool {
        bool(defaults, requireTouchIDKey, fallback: defaultRequireTouchID)
    }

    /// "Forget This Mac": the login field starts empty again.
    static func clearLastUsername(in defaults: UserDefaults) {
        defaults.removeObject(forKey: lastUsernameKey)
    }

    /// Writes the "Keep me signed in" preference (the only writer: both
    /// toggles go through AppSession.setKeepSignedIn).
    static func setKeepsSignedIn(_ keep: Bool, in defaults: UserDefaults) {
        defaults.set(keep, forKey: keepSignedInKey)
    }

    /// A sign-in completed: remember `name` for the login field only when
    /// "Keep me signed in" is on; otherwise forget any earlier one.
    static func recordSignIn(username name: String, in defaults: UserDefaults) {
        if keepsSignedIn(defaults) {
            setLastUsername(name, in: defaults)
        } else {
            clearLastUsername(in: defaults)
        }
    }

    /// A sign-out: the remembered username stays only while "Keep me
    /// signed in" is on.
    static func recordSignOut(in defaults: UserDefaults) {
        if !keepsSignedIn(defaults) { clearLastUsername(in: defaults) }
    }

    static func setLastUsername(_ name: String, in defaults: UserDefaults) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        defaults.set(trimmed, forKey: lastUsernameKey)
    }

    static func maxConcurrentUploads(_ defaults: UserDefaults) -> Int {
        clampedConcurrency(defaults, key: maxConcurrentUploadsKey, fallback: defaultMaxConcurrentUploads)
    }

    static func maxConcurrentDownloads(_ defaults: UserDefaults) -> Int {
        clampedConcurrency(defaults, key: maxConcurrentDownloadsKey, fallback: defaultMaxConcurrentDownloads)
    }

    static func asksDownloadDestination(_ defaults: UserDefaults) -> Bool {
        bool(defaults, askDownloadDestinationKey, fallback: defaultAskDownloadDestination)
    }

    static func opensTransfersOnStart(_ defaults: UserDefaults) -> Bool {
        bool(defaults, opensTransfersOnStartKey, fallback: defaultOpensTransfersOnStart)
    }

    static func confirmsTrash(_ defaults: UserDefaults) -> Bool {
        !bool(defaults, suppressTrashConfirmationKey, fallback: defaultSuppressTrashConfirmation)
    }

    static func downloadFolderBookmark(_ defaults: UserDefaults) -> Data? {
        defaults.data(forKey: downloadFolderBookmarkKey)
    }

    /// Stores a new default download folder (bookmark + display path).
    static func setDownloadFolder(bookmark: Data, path: String, in defaults: UserDefaults) {
        defaults.set(bookmark, forKey: downloadFolderBookmarkKey)
        defaults.set(path, forKey: downloadFolderPathKey)
    }

    /// Forgets the default download folder (it stays "Ask every time").
    static func clearDownloadFolder(in defaults: UserDefaults) {
        defaults.removeObject(forKey: downloadFolderBookmarkKey)
        defaults.removeObject(forKey: downloadFolderPathKey)
    }

    /// Stored value clamped to the stepper range; absent/zero → fallback.
    private static func clampedConcurrency(_ defaults: UserDefaults, key: String, fallback: Int) -> Int {
        let stored = defaults.integer(forKey: key)
        guard stored > 0 else { return fallback }
        return min(max(stored, concurrencyRange.lowerBound), concurrencyRange.upperBound)
    }

    /// `bool(forKey:)` reads absent as false; default-on settings need the
    /// explicit fallback.
    private static func bool(_ defaults: UserDefaults, _ key: String, fallback: Bool) -> Bool {
        defaults.object(forKey: key) as? Bool ?? fallback
    }
}

/// Fixed help/support links (Help menu, F8.4-U7).
enum HelpLinks {
    static let repository = "https://github.com/errrepe/Nucleon-Transfer"
    /// The repository itself (Settings › About "Source Code").
    static let source = URL(string: repository)
    static let readme = URL(string: repository + "#readme")
    /// GitHub anchor of README's "## Known limitations (alpha)".
    static let knownLimitations = URL(string: repository + "#known-limitations-alpha")
    static let newIssue = URL(string: repository + "/issues/new")
    static let security = URL(string: repository + "/blob/main/SECURITY.md")
}
