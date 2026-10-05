// Nucleon Transfer — banners above the folder table (F8.4-U1/U3).
// One thin strip per condition, stacked above FolderView's table (the
// Photos read-only pattern): Photos read-only, uploads blocked
// by Proton (code 2000, dismissible, Learn More → README), and "Couldn't
// refresh" when a reload failed but earlier rows are still on screen.
// System materials only; no custom glass on content.
import SwiftUI

/// Shared copy for the uploads-blocked state — the banner and every
/// disabled upload control's `.help` say the same thing.
enum UploadsBlockedCopy {
    static let message: LocalizedStringResource =
        "Uploads aren't available yet. Proton hasn't approved this app for uploads. Downloads work normally."
    /// README "Known limitations (alpha)" section on GitHub (single
    /// source: HelpLinks).
    static var learnMoreURL: URL? { HelpLinks.knownLimitations }
}

/// Common chrome for the strips: callout text on a regular material bar.
private struct BannerStrip<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        HStack(spacing: 8) { content }
            .font(.callout)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.regularMaterial)
    }
}

struct PhotosReadOnlyBanner: View {
    var body: some View {
        BannerStrip {
            Label("Photos is read-only in Nucleon Transfer.", systemImage: "info.circle")
                .foregroundStyle(.secondary)
        }
    }
}

/// F8.4-U1: shown once per run after Proton refused an upload with code
/// 2000. Closing it keeps the upload controls disabled.
struct UploadsBlockedBanner: View {
    /// Bumped on every refused upload — wiggles the warning icon.
    var refusals = 0
    var onDismiss: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        BannerStrip {
            // No vertical fixedSize: probed at a narrow width it reported a
            // height taller than the window, and the whole window content
            // was pushed up under the toolbar (live check). The label gets
            // the width first and wraps to at most three lines.
            Label {
                Text(UploadsBlockedCopy.message)
                    .lineLimit(1...3)
            } icon: {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.yellow)
                    // "That didn't work" for a drop onto a visible banner;
                    // a pulse (no movement) under Reduce Motion.
                    .symbolEffect(.wiggle, value: reduceMotion ? 0 : refusals)
                    .symbolEffect(.pulse, value: reduceMotion ? refusals : 0)
            }
            .layoutPriority(1)
            Spacer(minLength: 8)
            if let url = UploadsBlockedCopy.learnMoreURL {
                Link("Learn More", destination: url)
            }
            Button(action: onDismiss) {
                // The bare glyph was an 8-pt hit target (live audit) —
                // the padded label is what a borderless button hit-tests.
                Image(systemName: "xmark")
                    .frame(width: 22, height: 22)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help("Dismiss")
            .accessibilityLabel("Dismiss")
        }
        .accessibilityElement(children: .contain)
    }
}

/// F8.4-U3: a reload failed while cached rows stay on screen — the table
/// keeps the earlier listing, this strip says so and offers a retry.
struct RefreshFailedBanner: View {
    /// The mapped failure (UserFacingError), exposed as the tooltip.
    let message: String
    var onRetry: () -> Void

    var body: some View {
        BannerStrip {
            Label("Couldn't refresh. Showing earlier results.", systemImage: "exclamationmark.arrow.circlepath")
                .help(message)
            Spacer(minLength: 8)
            Button("Try Again", action: onRetry)
                .controlSize(.small)
        }
    }
}

#if DEBUG
#Preview("Banners — Light") {
    VStack(spacing: 0) {
        PhotosReadOnlyBanner()
        UploadsBlockedBanner {}
        RefreshFailedBanner(message: "Network issue.") {}
    }
    .frame(width: 720)
    .preferredColorScheme(.light)
}

#Preview("Banners — Dark") {
    VStack(spacing: 0) {
        PhotosReadOnlyBanner()
        UploadsBlockedBanner {}
        RefreshFailedBanner(message: "Network issue.") {}
    }
    .frame(width: 720)
    .preferredColorScheme(.dark)
}
#endif
