// Nucleon Transfer — the transfers popover (F7 S3.2, spec 6.5).
// 380×440: header ("Transfers" + ⋯ menu), then a List with Active /
// Failed / Completed sections (only non-empty ones), uploads and downloads
// merged newest-first via TransferDisplay. Pure inputs + closures so the
// same view renders offline previews; TransfersToolbarButton wires it to
// the session's UploadCoordinator + TransferActivityStore.
// F8.4-U6: inset list, section headers with counts ("Failed (3)") and a
// once-a-second tick while anything is in flight, so speed/ETA refresh
// (and fade out when a transfer stalls) between progress snapshots.
// Polish pass: rows animate as they move between sections or leave
// ("Clear Finished"), the empty state crossfades with the list, section
// counts roll and the intake-error footer fades in.
import SwiftUI

struct TransfersPanel: View {
    /// Every operation the rows/menu can trigger, keyed by job/record UUID.
    /// Defaults are no-ops so previews and partial wiring stay safe.
    struct Handlers {
        var pause: (UUID) -> Void = { _ in }
        var resume: (UUID) -> Void = { _ in }
        var cancel: (UUID) -> Void = { _ in }
        var retry: (UUID) -> Void = { _ in }
        var removeUpload: (UUID) -> Void = { _ in }
        var removeDownload: (UUID) -> Void = { _ in }
        var cancelDownload: (UUID) -> Void = { _ in }
        var revealDownload: (UUID) -> Void = { _ in }
        var pauseAll: () -> Void = {}
        var retryAllFailed: () -> Void = {}
        var clearFinished: () -> Void = {}
    }

    let uploads: [TransferJob]
    let downloads: [DownloadRecord]
    /// Job ID → "My Files › Projects" breadcrumb (UploadCoordinator).
    let destinationNames: [UUID: String]
    /// Download record ID → local file/folder URL for "Show in Finder".
    let revealURLs: [UUID: URL]
    /// Last intake failure, already user-facing (UploadCoordinator).
    let lastError: String?
    /// Smoothed rate by item id at a render time (TransferActivityStore);
    /// nil hides speed/ETA. Defaults to none for previews.
    var bytesPerSecond: (String, Date) -> Double? = { _, _ in nil }
    var handlers = Handlers()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private func sections(at now: Date) -> [TransferDisplaySection] {
        TransferDisplay.sections(
            uploads: uploads,
            downloads: downloads,
            destinationName: { destinationNames[$0] },
            bytesPerSecond: { bytesPerSecond($0, now) }
        )
    }

    private var hasActive: Bool {
        TransferDisplay.activeCount(uploads: uploads, downloads: downloads) > 0
    }

    private var canPauseAll: Bool {
        uploads.contains { $0.state == .queued || $0.state == .uploading }
    }

    private var hasFailedUploads: Bool {
        uploads.contains { $0.state == .failed }
    }

    /// "Clear Finished" clears finished downloads AND removes done uploads.
    private var hasFinished: Bool {
        downloads.contains { $0.state != .downloading }
            || uploads.contains { $0.state == .done }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            if let lastError, !lastError.isEmpty {
                VStack(spacing: 0) {
                    Divider()
                    Text(lastError)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                        .help(lastError)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                }
                .transition(.opacity)
            }
        }
        .animation(Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion), value: lastError)
        .frame(width: 380, height: 440, alignment: .top)
    }

    private var header: some View {
        HStack {
            Text("Transfers")
                .font(.headline)
            Spacer()
            Menu {
                Button("Pause All", action: handlers.pauseAll)
                    .disabled(!canPauseAll)
                Button("Retry Failed", action: handlers.retryAllFailed)
                    .disabled(!hasFailedUploads)
                Divider()
                Button("Clear Finished", action: handlers.clearFinished)
                    .disabled(!hasFinished)
            } label: {
                Label("Transfer Actions", systemImage: "ellipsis")
                    .labelStyle(.iconOnly)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Transfer Actions")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private var content: some View {
        // Paused (no ticks) when idle; one schedule either way so the
        // list keeps its identity (and scroll position) across the flip.
        TimelineView(.animation(minimumInterval: 1, paused: !hasActive)) { context in
            list(sections(at: context.date))
        }
        // Fill the panel below the header: the empty state doesn't grow on
        // its own, and a shorter stack would sit centered in the fixed
        // frame with blank bands above the header and below the content.
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func list(_ sections: [TransferDisplaySection]) -> some View {
        listContent(sections)
            // Animate membership changes only — not every 1 s tick.
            .animation(
                Motion.adaptive(Motion.snappy, reduceMotion: reduceMotion),
                // Membership per section, order-free: Active is sorted by
                // updatedAt, which moves on every job start — keying on
                // display order would shuffle rows during a big upload.
                value: sections.map { Set($0.items.map(\.id)) }
            )
    }

    @ViewBuilder
    private func listContent(_ sections: [TransferDisplaySection]) -> some View {
        if sections.isEmpty {
            ContentUnavailableView(
                "No Transfers",
                systemImage: "arrow.up.arrow.down",
                description: Text("Files you upload or download appear here.")
            )
            .transition(.opacity)
        } else {
            List {
                ForEach(sections) { section in
                    Section {
                        ForEach(section.items) { item in
                            TransferRow(item: item, actions: actions(for: item))
                        }
                    } header: {
                        // "Failed (3)": the count rolls as rows come and go
                        // (it only changes with membership, never per tick).
                        Text(section.title)
                            .contentTransition(Motion.numeric(
                                Double(section.items.count), reduceMotion: reduceMotion
                            ))
                    }
                }
            }
            .listStyle(.inset)
            .transition(.opacity)
        }
    }

    /// Per-state action set for a row — the same shape the retired queue
    /// view's `actions(_:)` had. Downloads have no pause/retry API: an
    /// in-flight download can be cancelled (F8.2-R5), a done one gets
    /// "Show in Finder" and a failed/cancelled one can only be dismissed.
    private func actions(for item: TransferDisplayItem) -> TransferRowActions {
        guard let uuid = UUID(uuidString: item.id) else { return TransferRowActions() }
        switch item.direction {
        case .upload:
            guard let job = uploads.first(where: { $0.id == uuid }) else {
                return TransferRowActions()
            }
            switch job.state {
            case .queued, .uploading:
                return TransferRowActions(
                    pause: { handlers.pause(uuid) },
                    cancel: { handlers.cancel(uuid) }
                )
            case .paused:
                return TransferRowActions(
                    resume: { handlers.resume(uuid) },
                    cancel: { handlers.cancel(uuid) }
                )
            case .failed, .cancelled:
                return TransferRowActions(
                    retry: { handlers.retry(uuid) },
                    remove: { handlers.removeUpload(uuid) }
                )
            case .done:
                return TransferRowActions(
                    remove: { handlers.removeUpload(uuid) }
                )
            }
        case .download:
            guard let record = downloads.first(where: { $0.id == uuid }) else {
                return TransferRowActions()
            }
            switch record.state {
            case .downloading:
                return TransferRowActions(
                    cancel: { handlers.cancelDownload(uuid) }
                )
            case .done:
                guard revealURLs[uuid] != nil else { return TransferRowActions() }
                return TransferRowActions(
                    reveal: { handlers.revealDownload(uuid) }
                )
            case .failed, .cancelled:
                return TransferRowActions(
                    remove: { handlers.removeDownload(uuid) }
                )
            }
        }
    }
}

#if DEBUG
#Preview("Empty — Light") {
    TransfersPanel(
        uploads: [], downloads: [], destinationNames: [:],
        revealURLs: [:], lastError: nil
    )
    .preferredColorScheme(.light)
}

#Preview("Empty — Dark") {
    TransfersPanel(
        uploads: [], downloads: [], destinationNames: [:],
        revealURLs: [:], lastError: nil
    )
    .preferredColorScheme(.dark)
}

#Preview("Mixed — Light") {
    TransfersPanel(
        uploads: [PreviewFixtures.uploadJobs[0]],
        downloads: PreviewFixtures.downloadRecords,
        destinationNames: PreviewFixtures.uploadDestinationNames,
        revealURLs: PreviewFixtures.downloadRevealURLs,
        lastError: nil
    )
    .preferredColorScheme(.light)
}

#Preview("Mixed — Dark") {
    TransfersPanel(
        uploads: [PreviewFixtures.uploadJobs[0]],
        downloads: PreviewFixtures.downloadRecords,
        destinationNames: PreviewFixtures.uploadDestinationNames,
        revealURLs: PreviewFixtures.downloadRevealURLs,
        lastError: nil
    )
    .preferredColorScheme(.dark)
}

#Preview("Failure — Light") {
    TransfersPanel(
        uploads: PreviewFixtures.uploadJobs,
        downloads: PreviewFixtures.downloadRecords + [PreviewFixtures.failedDownload],
        destinationNames: PreviewFixtures.uploadDestinationNames,
        revealURLs: PreviewFixtures.downloadRevealURLs,
        lastError: "big.iso: Upload preparation failed."
    )
    .preferredColorScheme(.light)
}

#Preview("Failure — Dark") {
    TransfersPanel(
        uploads: PreviewFixtures.uploadJobs,
        downloads: PreviewFixtures.downloadRecords + [PreviewFixtures.failedDownload],
        destinationNames: PreviewFixtures.uploadDestinationNames,
        revealURLs: PreviewFixtures.downloadRevealURLs,
        lastError: "big.iso: Upload preparation failed."
    )
    .preferredColorScheme(.dark)
}
#endif
