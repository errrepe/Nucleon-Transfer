// Nucleon Transfer — one row in the transfers popover (F7 S3.2, spec 6.5).
// Renders a TransferDisplayItem (built in Core/TransferDisplay): file icon,
// name, subtitle (red on failure, max 2 lines) and a small progress bar for
// in-flight rows. Action buttons are icon-only per spec 6.2 — the same
// per-state set the retired queue view had (Pause/Resume/Cancel/Retry/
// Remove) plus "Show in Finder" for completed downloads.
// F8.4-U6/U8: failed rows show the full error on hover and via "Show
// Details…" (alert with Copy); failure/cancellation carry an SF Symbol
// beside the subtitle (never color alone); VoiceOver reads each row as ONE
// element (name + status) whose buttons are exposed as named actions.
// Polish pass: the progress bar glides between snapshots and Pause/Resume
// is one button whose symbol morphs (replace effect) instead of swapping
// controls.
import AppKit
import SwiftUI

/// Icon-only action set for a row: one closure per possible button, nil =
/// hidden for this state. The panel resolves which apply (a failed
/// download, for instance, can only be dismissed — there is no download
/// retry API).
struct TransferRowActions {
    var pause: (() -> Void)?
    var resume: (() -> Void)?
    var cancel: (() -> Void)?
    var retry: (() -> Void)?
    var remove: (() -> Void)?
    var reveal: (() -> Void)?
}

struct TransferRow: View {
    let item: TransferDisplayItem
    var actions = TransferRowActions()
    @State private var showDetails = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(nsImage: FileIconCache.icon(forName: item.name, isFolder: item.isFolder))
                .resizable()
                .frame(width: 20, height: 20)
                .padding(.top, 1)
                // Decorative: name + subtitle already give VoiceOver context.
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(item.name)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(item.name)
                HStack(alignment: .firstTextBaseline, spacing: 3) {
                    if let symbol = item.statusSymbol {
                        Image(systemName: symbol)
                            .imageScale(.small)
                            .transition(.symbolEffect(.appear))
                    }
                    Text(item.subtitle)
                        .lineLimit(2)
                        .monospacedDigit() // "42% · 3.2 MB/s" ticks up
                }
                .font(.caption)
                .foregroundStyle(item.isFailed ? .red : .secondary)
                // Full text on hover: errors truncate at two lines.
                .help(item.subtitle)
                if let progress = item.progress {
                    ProgressView(value: progress)
                        .controlSize(.small)
                        // Snapshots land in steps; ease between them.
                        .animation(reduceMotion ? nil : .smooth(duration: 0.5), value: progress)
                        .accessibilityLabel("\(item.name) progress")
                        .accessibilityValue(item.progressText ?? "")
                        .transition(.opacity)
                }
            }
            .animation(reduceMotion ? nil : Motion.snappy, value: item.statusSymbol)
            .animation(reduceMotion ? nil : Motion.snappy, value: item.progress == nil)
            Spacer(minLength: 4)
            actionButtons
        }
        .padding(.vertical, 2)
        .contextMenu { contextActions }
        // One VoiceOver stop per row: name + status/progress, buttons as
        // named actions (rotor "Actions") instead of separate stops.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(item.name)
        .accessibilityValue(item.accessibilityValue)
        .accessibilityActions { contextActions }
        .alert(detailsTitle, isPresented: $showDetails) {
            Button("Copy") { copyDetails() }
            Button("OK", role: .cancel) {}
        } message: {
            Text(item.subtitle)
        }
    }

    private var detailsTitle: String {
        switch item.direction {
        case .upload: return String(localized: "Couldn’t Upload “\(item.name)”")
        case .download: return String(localized: "Couldn’t Download “\(item.name)”")
        }
    }

    private func copyDetails() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(item.subtitle, forType: .string)
    }

    /// Same actions as the icon buttons, as text items (F8.2-R5: "Cancel"
    /// reachable by right-click too). Empty for rows without actions.
    @ViewBuilder
    private var contextActions: some View {
        if let pause = actions.pause { Button("Pause", action: pause) }
        if let resume = actions.resume { Button("Resume", action: resume) }
        if let retry = actions.retry { Button("Retry", action: retry) }
        if item.isFailed { Button("Show Details…") { showDetails = true } }
        if let reveal = actions.reveal { Button("Show in Finder", action: reveal) }
        if let cancel = actions.cancel { Button("Cancel", action: cancel) }
        if let remove = actions.remove { Button("Remove", action: remove) }
    }

    @ViewBuilder
    private var actionButtons: some View {
        // Spec-6.2 glyphs; order matches the wireframe (⏸ ✕ · ↻ ✕ · 🔍).
        // Pause ⇄ Resume is ONE button (stable identity) so the glyph
        // morphs instead of one control replacing another.
        if let toggle = actions.resume ?? actions.pause {
            let paused = actions.resume != nil
            rowButton(
                paused ? "Resume" : "Pause",
                systemImage: paused ? "play.circle" : "pause.circle",
                action: toggle
            )
            .contentTransition(.symbolEffect(.replace))
        }
        if let retry = actions.retry {
            rowButton("Retry", systemImage: "arrow.clockwise.circle", action: retry)
        }
        if let reveal = actions.reveal {
            rowButton("Show in Finder", systemImage: "magnifyingglass.circle", action: reveal)
        }
        if let cancel = actions.cancel {
            rowButton("Cancel", systemImage: "xmark.circle", action: cancel)
                .accessibilityLabel("Cancel \(item.name)")
        }
        if let remove = actions.remove {
            rowButton("Remove", systemImage: "xmark.circle", action: remove)
        }
    }

    private func rowButton(
        _ label: LocalizedStringKey, systemImage: String, action: @escaping () -> Void
    ) -> some View {
        Button(label, systemImage: systemImage, action: action)
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help(label)
    }
}

#if DEBUG
#Preview("Row — Active Upload") {
    TransferRow(
        item: TransferDisplay.item(
            for: PreviewFixtures.uploadJobs[0],
            destinationName: "My Files › Projects"
        ),
        actions: TransferRowActions(pause: {}, cancel: {})
    )
    .padding()
    .frame(width: 340)
}

#Preview("Row — Failed / Done") {
    VStack(alignment: .leading) {
        TransferRow(
            item: TransferDisplay.item(
                for: PreviewFixtures.uploadJobs[1],
                destinationName: "My Files › Projects"
            ),
            actions: TransferRowActions(retry: {}, remove: {})
        )
        Divider()
        TransferRow(
            item: TransferDisplay.item(for: PreviewFixtures.downloadRecords[1]),
            actions: TransferRowActions(reveal: {})
        )
        Divider()
        TransferRow(
            item: TransferDisplay.item(
                for: DownloadRecord(name: "Photos.zip", kind: .file, state: .cancelled)
            ),
            actions: TransferRowActions(remove: {})
        )
    }
    .padding()
    .frame(width: 340)
}
#endif
