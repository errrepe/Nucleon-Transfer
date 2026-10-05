// Nucleon Transfer — panel intake decision (pure, AppKit-free).
// Extracts the OK/cancel + URL resolution for NSOpenPanel sheet flows so the
// async completion paths in the view-models never block MainActor and the
// cancel-vs-confirm mapping is unit-testable without AppKit.
//
// Bug context (2026-10-01, sample /tmp/nt-sample.txt): the pre-F7 browser
// view-model's download picker called NSSavePanel.runModal() on the MainActor. When the
// app was not active/key the modal loop never returned and the whole UI died.
// Fix: beginSheetModal(for:) on the key window (fallback: begin app-modal),
// continue in the completion handler; cancel only sets a "cancelled" status.
import Foundation

/// Pure mapping for NSOpenPanel outcomes. `responseOK` mirrors
/// `response == .OK`; callers pass `panel.url` / `panel.urls` through.
enum PanelIntake {
    /// Download destination: non-nil only on explicit OK + URL.
    /// Cancel/dismiss (any non-OK) or nil URL → nil: the caller must set a
    /// "cancelled" status and never proceed (never blocks).
    static func downloadDestination(responseOK: Bool, url: URL?) -> URL? {
        guard responseOK, let url else { return nil }
        return url
    }

    /// Upload intake: confirmed URLs only on OK; otherwise empty (= no-op,
    /// caller leaves status untouched).
    static func uploadURLs(responseOK: Bool, urls: [URL]) -> [URL] {
        guard responseOK else { return [] }
        return urls
    }

    /// Status line for a dismissed download panel (never blocks, never proceeds).
    static func downloadCancelledStatus(rowName: String) -> String {
        String(localized: "Download cancelled (\(rowName))")
    }
}
