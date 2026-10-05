// Nucleon Transfer — banners above the folder table (F8.4-U1).
// One thin strip per condition, stacked in FolderView's top safe-area
// inset (the Photos read-only pattern): Photos read-only and uploads
// blocked by Proton (code 2000, dismissible, Learn More → README).
// System materials only; no custom glass on content.
import SwiftUI

/// Shared copy for the uploads-blocked state — the banner and every
/// disabled upload control's `.help` say the same thing.
enum UploadsBlockedCopy {
    static let message: LocalizedStringResource =
        "Uploads aren't available yet. Proton hasn't approved this app for uploads. Downloads work normally."
    /// README "Known limitations (alpha)" section on GitHub.
    static let learnMoreURL = URL(string: "https://github.com/errrepe/Nucleon-Transfer#known-limitations-alpha")
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
    var onDismiss: () -> Void

    var body: some View {
        BannerStrip {
            Label {
                Text(UploadsBlockedCopy.message)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.yellow)
            }
            Spacer(minLength: 8)
            if let url = UploadsBlockedCopy.learnMoreURL {
                Link("Learn More", destination: url)
            }
            Button("Dismiss", systemImage: "xmark", action: onDismiss)
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .help("Dismiss")
        }
        .accessibilityElement(children: .contain)
    }
}

#if DEBUG
#Preview("Banners — Light") {
    VStack(spacing: 0) {
        PhotosReadOnlyBanner()
        UploadsBlockedBanner {}
    }
    .frame(width: 720)
    .preferredColorScheme(.light)
}

#Preview("Banners — Dark") {
    VStack(spacing: 0) {
        PhotosReadOnlyBanner()
        UploadsBlockedBanner {}
    }
    .frame(width: 720)
    .preferredColorScheme(.dark)
}
#endif
