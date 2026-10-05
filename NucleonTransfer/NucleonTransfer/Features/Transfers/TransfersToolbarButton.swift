// Nucleon Transfer — toolbar entry to the transfers popover (F7 S3.2).
// Lives in the FolderView toolbar (.primaryAction, trailing). The badge
// counts in-flight transfers; the popover binds to
// `TransferActivityStore.presentTransfers`, which UploadCoordinator also
// flips on intake so the panel opens on the first upload.
// Badge note: `.badge(_:)` compiles on macOS but only renders inside
// TabView/list rows — it is a no-op on an NSToolbarItem-backed button —
// so the count rides on a small capsule overlay instead.
// F8.4-U6: the capsule is accent-tinted for in-flight transfers and turns
// red (with an exclamation glyph) only when something failed and nothing
// runs any more; while transfers run, a failure adds a small red
// exclamation dot to the tinted count (F8.4 review). Upload speed
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
            // The toolbar clips the item to its label's bounds, so a badge
            // offset past the icon's edge was cut in half (live check, twice).
            // The icon gets a fixed, slightly larger frame (stable whether
            // or not a badge shows) and the badge sits inside its corner.
            Label {
                Text("Transfers")
            } icon: {
                Image(systemName: "arrow.up.arrow.down")
                    .frame(width: 30, height: 22)
                    .overlay(alignment: .topTrailing) { badge }
            }
        }
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

    /// Count capsule: accent tint while transfers run (a red "!" dot on
    /// its leading edge when some also failed), red + "!" glyph when only
    /// failures remain (state never conveyed by color alone).
    /// `monospacedDigit` keeps the capsule width stable while the count
    /// changes. Hidden from VoiceOver — the button label carries it.
    @ViewBuilder
    private var badge: some View {
        switch badgeState {
        case .none:
            EmptyView()
        case let .active(count, failed):
            capsule(fill: AnyShapeStyle(.tint)) {
                Text(count, format: .number)
            }
            .overlay(alignment: .topLeading) {
                if failed > 0 { failedMarker }
            }
        case let .failed(count):
            capsule(fill: AnyShapeStyle(.red)) {
                HStack(spacing: 1) {
                    Image(systemName: "exclamationmark")
                        .fontWeight(.bold)
                    Text(count, format: .number)
                }
            }
        }
    }

    /// Small red "!" dot riding on the active capsule (failures exist
    /// while other transfers still run).
    private var failedMarker: some View {
        Image(systemName: "exclamationmark")
            .font(.system(size: 6, weight: .black))
            .foregroundStyle(.white)
            .frame(width: 9, height: 9)
            .background(.red, in: Circle())
            .offset(x: -3, y: -1)
            .accessibilityHidden(true)
    }

    private func capsule<Content: View>(
        fill: AnyShapeStyle, @ViewBuilder content: () -> Content
    ) -> some View {
        content()
            .font(.caption2)
            .monospacedDigit()
            .foregroundStyle(.white)
            .padding(.horizontal, 4)
            .padding(.vertical, 1)
            .background(fill, in: Capsule())
            .accessibilityHidden(true)
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
