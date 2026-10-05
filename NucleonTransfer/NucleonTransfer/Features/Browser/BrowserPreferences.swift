// Nucleon Transfer — browser view preferences (F8.4-U3).
// @AppStorage keys shared by the browser views and the menu commands, so
// View ▸ Show Path Bar and the path bar inset read the same default.
import Foundation

enum BrowserPreferences {
    /// View ▸ Show Path Bar (⌥⌘P) — off by default, like Finder.
    static let showPathBarKey = "browser.showPathBar"
}
