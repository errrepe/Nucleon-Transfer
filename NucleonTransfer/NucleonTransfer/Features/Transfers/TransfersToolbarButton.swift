// Nucleon Transfer — toolbar entry to the transfers popover (F7 S3.2).
// Lives in the FolderView toolbar (.primaryAction, trailing). The badge
// counts in-flight transfers; the popover binds to
// `TransferActivityStore.presentTransfers`, which UploadCoordinator also
// flips on intake so the panel opens on the first upload.
// Badge note: on macOS 26 `.badge(_:)` on the toolbar button maps to the
// native NSToolbarItem badge, drawn by the system OUTSIDE the glass
// capsule (live check — hand-drawn overlays were clipped to the item or
// covered the icon). The native badge is always red, so state rides in
// the text: "3" in flight, "3!" in flight with failures, "!3" only
// failures left (F8.4-U6 — never color alone). Upload speed
// samples come from UploadCoordinator's snapshot listener (F8.4-U7b), not
// from this view.
import AppKit
import SwiftUI

struct TransfersToolbarButton: View {
    /// Passed in by FolderView — never read from the environment. This
    /// button sits in a ToolbarItem of every pushed FolderView, where an
    /// object injected outside the NavigationStack can be missing
    /// (crash B1: EnvironmentValues assert on a background-hosted item).
    let session: AppSession

    private var badgeState: TransferBadge {
        TransferDisplay.badge(
            uploads: session.uploads?.jobs ?? [],
            downloads: session.activity.downloads
        )
    }

    var body: some View {
        @Bindable var activity = session.activity
        Button {
            activity.presentTransfers.toggle()
        } label: {
            Label("Transfers", systemImage: "arrow.up.arrow.down")
        }
        .badge(badgeText)
        // M4: match the View-menu wording ("Show Transfers") and say
        // what the button does; the active/failed count rides along. The
        // AX label keeps the shorter "Transfers" form.
        .help(
            badgeState.summary.map { String(localized: "Show Transfers — \($0)") }
                ?? String(localized: "Show Transfers")
        )
        .accessibilityLabel(
            badgeState.summary.map { String(localized: "Transfers, \($0)") }
                ?? String(localized: "Transfers")
        )
        .popover(isPresented: $activity.presentTransfers, arrowEdge: .bottom) {
            // TransfersPanel takes pure inputs today; the injection is a
            // safety net for any future panel child that reads the
            // environment — popover content is hosted off-hierarchy too.
            panel
                .environment(session)
        }
    }

    /// Native toolbar badge text; nil hides it. Digits are localized.
    private var badgeText: Text? {
        switch badgeState {
        case .none:
            nil
        case let .active(count, failed):
            Text(verbatim: failed > 0 ? "\(count.formatted())!" : count.formatted())
        case let .failed(count):
            Text(verbatim: "!\(count.formatted())")
        }
    }

    private var panel: TransfersPanel {
        TransfersPanel(
            uploads: session.uploads?.jobs ?? [],
            downloads: session.activity.downloads,
            destinationNames: session.uploads?.destinationNames ?? [:],
            revealURLs: session.activity.revealURLs,
            lastError: session.uploads?.lastError,
            bytesPerSecond: { [activity = session.activity] id, date in
                activity.bytesPerSecond(id: id, at: date)
            },
            handlers: TransfersPanel.Handlers(
                pause: { [session] id in
                    Task { await session.uploads?.pause(id) }
                },
                resume: { [session] id in
                    Task { await session.uploads?.resume(id) }
                },
                cancel: { [session] id in
                    Task { await session.uploads?.cancel(id) }
                },
                retry: { [session] id in
                    Task { await session.uploads?.relaunch(id) }
                },
                removeUpload: { [session] id in
                    Task { await session.uploads?.remove(id) }
                },
                removeDownload: { [session] id in
                    session.activity.removeDownload(id: id)
                },
                cancelDownload: { [session] id in
                    session.downloads?.cancel(id)
                },
                revealDownload: { [session] id in
                    // revealURLs is memory-only: the URL exists for this
                    // process only, never persisted — safe to hand to
                    // NSWorkspace here.
                    if let url = session.activity.revealURLs[id] {
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                },
                pauseAll: { [session] in
                    Task { await session.uploads?.pauseAll() }
                },
                retryAllFailed: { [session] in
                    Task { await session.uploads?.relaunchAllFailed() }
                },
                clearFinished: { [session] in
                    session.activity.clearFinished()
                    Task {
                        guard let uploads = session.uploads else { return }
                        // Spec 6.5: finished = done uploads + cleared
                        // download records. Failed uploads stay (Retry).
                        for job in uploads.jobs where job.state == .done {
                            await uploads.remove(job.id)
                        }
                    }
                }
            )
        )
    }
}

#if DEBUG
#Preview("Toolbar Button") {
    // Preview session has no UploadCoordinator — the popover then shows
    // download fixtures only, which still exercises the panel path.
    let session = PreviewFixtures.session()
    session.activity.downloads = PreviewFixtures.downloadRecords
    return TransfersToolbarButton(session: session)
        .padding(40)
}

#Preview("Toolbar Button — Active + Failed") {
    // In-flight fixtures plus one failure: tinted count with the red dot.
    let session = PreviewFixtures.session()
    session.activity.downloads = PreviewFixtures.downloadRecords + [PreviewFixtures.failedDownload]
    return TransfersToolbarButton(session: session)
        .padding(40)
}

#Preview("Toolbar Button — Failed") {
    // Nothing in flight any more: the red failed capsule.
    let session = PreviewFixtures.session()
    session.activity.downloads = PreviewFixtures.downloadRecords.filter { $0.state != .downloading }
        + [PreviewFixtures.failedDownload]
    return TransfersToolbarButton(session: session)
        .padding(40)
}
#endif
