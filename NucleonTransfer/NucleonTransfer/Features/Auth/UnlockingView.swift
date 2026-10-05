// Nucleon Transfer — key-unlock progress screen (F7 S4.1).
// Shown while AppSession.phase == .unlocking: the session is in, the
// password is decrypting the local key hierarchy. Pure status — nothing
// to interact with, everything happens on-device. The reassurance line
// fades in only if unlocking takes a while (a fast unlock never shows it).
import SwiftUI

struct UnlockingView: View {
    var body: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.large)
            Text("Unlocking your encrypted drive…")
                .font(.headline)
            Text("This happens on your Mac. It can take a few seconds.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .delayedReveal(after: .seconds(1.5))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(minWidth: 420, minHeight: 320)
    }
}

#if DEBUG
#Preview("Light") {
    UnlockingView()
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    UnlockingView()
        .preferredColorScheme(.dark)
}
#endif
