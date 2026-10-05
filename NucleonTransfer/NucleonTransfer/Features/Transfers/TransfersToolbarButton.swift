// Nucleon Transfer — toolbar entry to the transfers popover (F7 S3.2).
// Lives in the FolderView toolbar (.primaryAction, trailing). The badge
// counts in-flight transfers; the popover binds to
// `TransferActivityStore.presentTransfers`, which UploadCoordinator also
// flips on intake so the panel opens on the first upload.
// Badge note: `.badge(_:)` compiles on macOS but only renders inside
// TabView/list rows — it is a no-op on an NSToolbarItem-backed button —
// so the count rides on a small capsule overlay instead.
import AppKit
import SwiftUI

struct TransfersToolbarButton: View {
    /// Passed in by FolderView — never read from the environment. This
    /// button sits in a ToolbarItem of every pushed FolderView, where an
    /// object injected outside the NavigationStack can be missing
    /// (crash B1: EnvironmentValues assert on a background-hosted item).
    let session: AppSession

    private var activeCount: Int {
        TransferDisplay.activeCount(
            uploads: session.uploads?.jobs ?? [],
            downloads: session.activity.downloads
        )
    }

    var body: some View {
        @Bindable var activity = session.activity
        Button("Transfers", systemImage: "arrow.up.arrow.down") {
            activity.presentTransfers.toggle()
        }
        // M4: match the View-menu wording ("Show Transfers") and say
        // what the button does; the count rides along while items are
        // in flight. The AX label keeps the shorter "Transfers" form.
        .help(
            activeCount > 0
                ? "Show Transfers — \(activeCount) active"
                : "Show Transfers"
        )
        .accessibilityLabel(
            activeCount > 0 ? "Transfers, \(activeCount) active" : "Transfers"
        )
        .overlay(alignment: .topTrailing) { badge }
        .popover(isPresented: $activity.presentTransfers, arrowEdge: .bottom) {
            // TransfersPanel takes pure inputs today; the injection is a
            // safety net for any future panel child that reads the
            // environment — popover content is hosted off-hierarchy too.
            panel
                .environment(session)
        }
    }

    /// Active-count capsule. `monospacedDigit` keeps the capsule width
    /// stable while the count changes.
    @ViewBuilder
    private var badge: some View {
        if activeCount > 0 {
            Text(activeCount, format: .number)
                .font(.caption2)
                .monospacedDigit()
                .foregroundStyle(.white)
                .padding(.horizontal, 4)
                .padding(.vertical, 1)
                .background(.red, in: Capsule())
                .offset(x: 6, y: -4)
                .accessibilityHidden(true)
        }
    }

    private var panel: TransfersPanel {
        TransfersPanel(
            uploads: session.uploads?.jobs ?? [],
            downloads: session.activity.downloads,
            destinationNames: session.uploads?.destinationNames ?? [:],
            revealURLs: session.activity.revealURLs,
            lastError: session.uploads?.lastError,
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
#endif
