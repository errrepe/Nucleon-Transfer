// Nucleon Transfer — root switch between the signed-in shell and the auth
// flow (F7 S4.1). One screen per phase: login covers signedOut + signingIn
// (its own busy sub-state), needsTwoFactor gets the TOTP prompt, unlocking
// the key-decryption spinner, restoring (F8.5) the "Signing in…" spinner
// while a remembered session resumes — all crossfading on a short opacity.
// The `.task` kicks off that restore when "Keep me signed in" stored one
// (no-op otherwise, and for the demo session) — once per app launch:
// reopening the window doesn't restore again (AppSession.restoreOnLaunch).
// Polish pass: the crossfade gained a slight settle-in scale and a smooth
// spring (plain crossfade under Reduce Motion — see Motion).
import SwiftUI

struct RootView: View {
    @Environment(AppSession.self) private var session
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            switch session.phase {
            case .signedIn:
                MainView()
                    .transition(phaseTransition)
            case .signedOut, .signingIn:
                LoginView()
                    .transition(phaseTransition)
            case .needsTwoFactor:
                TwoFactorView()
                    .transition(phaseTransition)
            case .unlocking:
                UnlockingView()
                    .transition(phaseTransition)
            case .restoring:
                RestoringView()
                    .transition(phaseTransition)
            }
        }
        .task {
            await session.restoreOnLaunch()
        }
        .animation(Motion.adaptive(Motion.smooth, reduceMotion: reduceMotion), value: session.phase)
        // S4.2: publish the session for app-level menu commands (Sign
        // Out, Show Transfers) — they must work even where no BrowserModel
        // is on screen (e.g. the root-load error state).
        .focusedSceneValue(\.appSession, session)
    }

    private var phaseTransition: AnyTransition {
        Motion.phase(reduceMotion: reduceMotion)
    }
}
