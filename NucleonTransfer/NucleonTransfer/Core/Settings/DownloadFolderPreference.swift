// Nucleon Transfer — default download folder resolution (F8.4-U7).
// Decides whether a download batch asks for a destination or goes straight
// to the bookmarked default folder. AppKit-free: bookmark + scope calls go
// through LocalFileAccess so the decision is unit-tested without real
// grants. Any doubt (ask-every-time on, no bookmark, unresolvable bookmark,
// folder gone) falls back to asking — a download never lands somewhere
// the user can't see.
import Foundation

enum DownloadFolderPreference {
    enum Decision: Equatable, Sendable {
        /// Show the destination panel.
        case ask
        /// Save into `url`. The caller starts (and balances) security-
        /// scoped access, exactly as for a panel URL. `refreshedBookmark`
        /// is non-nil when the stored bookmark was stale — persist it.
        case folder(URL, refreshedBookmark: Data?)
    }

    static func decide(
        askEveryTime: Bool, bookmark: Data?, access: LocalFileAccess
    ) -> Decision {
        guard !askEveryTime, let bookmark,
              let resolved = try? access.resolveBookmark(bookmark)
        else { return .ask }
        // Existence needs the grant inside the sandbox; held only for the
        // check — the caller re-starts access for the batch.
        let scoped = access.startAccessing(resolved.url)
        defer { if scoped { access.stopAccessing(resolved.url) } }
        guard access.fileExists(resolved.url.path) else { return .ask }
        let refreshed = resolved.isStale ? (try? access.makeBookmark(resolved.url)) : nil
        return .folder(resolved.url, refreshedBookmark: refreshed)
    }

    /// Reads the stored preference from `defaults`, persisting a refreshed
    /// bookmark so the next launch resolves without the stale path.
    static func decide(defaults: UserDefaults, access: LocalFileAccess) -> Decision {
        let decision = decide(
            askEveryTime: AppSettings.asksDownloadDestination(defaults),
            bookmark: AppSettings.downloadFolderBookmark(defaults),
            access: access
        )
        if case let .folder(url, refreshed?) = decision {
            AppSettings.setDownloadFolder(bookmark: refreshed, path: url.path, in: defaults)
        }
        return decision
    }

    /// Download panel message: names the batch size so the user knows
    /// what the "Download Here" button commits to.
    static func panelMessage(itemCount: Int?) -> String {
        switch itemCount {
        case nil, 0?:
            String(localized: "Choose where to save the download.")
        case let count?:
            // Plural via inflection (catalog plural variants in the app;
            // English inflection where no catalog is bundled — swift test).
            String(AttributedString(localized: "Choose where to save ^[\(count) item](inflect: true).").characters)
        }
    }
}
