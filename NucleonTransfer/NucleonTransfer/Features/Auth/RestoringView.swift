// Nucleon Transfer — remembered-session progress screen (F8.5).
// Shown while AppSession.phase == .restoring: "Keep me signed in" stored a
// session and the app is refreshing it and unlocking the keys — no
// password needed. Same layout as UnlockingView; nothing to interact with.
// Polish pass: fades in after a beat, so a fast restore never flashes it.
import SwiftUI

struct RestoringView: View {
    var body: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.large)
            Text("Signing in…")
                .font(.headline)
        }
        .delayedReveal()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(minWidth: 420, minHeight: 320)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Light") {
    RestoringView()
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    RestoringView()
        .preferredColorScheme(.dark)
}
#endif
