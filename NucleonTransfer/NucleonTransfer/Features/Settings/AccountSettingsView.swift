// Nucleon Transfer — Settings › Account (F8.5-V3).
// "Keep me signed in" (same key as the login checkbox; off deletes the
// remembered session), "Require Touch ID" (re-seals / unseals the stored
// session through AppSession — a failure, e.g. a cancelled prompt when
// turning it off, flips the toggle back), and "Forget This Mac…" behind a
// confirmation: both Keychain items + the remembered username go, the
// current session keeps running. The Touch ID toggle is disabled (with
// the reason) while keep-signed-in is off or this Mac can't use Touch ID.
import SwiftUI

struct AccountSettingsView: View {
    @Environment(AppSession.self) private var session
    @AppStorage(AppSettings.keepSignedInKey)
    private var keepSignedIn = AppSettings.defaultKeepSignedIn
    @AppStorage(AppSettings.requireTouchIDKey)
    private var requireTouchID = AppSettings.defaultRequireTouchID
    /// LAContext.canEvaluatePolicy, sampled on appear (previews inject it).
    @State private var biometryAvailable: Bool
    @State private var confirmingForget = false
    @State private var isApplying = false
    /// Shown under the buttons after "Forget This Mac" ran.
    @State private var forgotten = false

    init(biometryAvailable: Bool? = nil) {
        _biometryAvailable = State(initialValue: biometryAvailable ?? BiometryAvailability.isAvailable())
    }

    /// Sign-in work in flight: changing the stored session now would race it.
    private var isBusy: Bool {
        switch session.phase {
        case .signingIn, .unlocking, .restoring: return true
        case .signedOut, .needsTwoFactor, .signedIn: return false
        }
    }

    var body: some View {
        Form {
            Section("Sign-In") {
                Toggle("Keep me signed in", isOn: $keepSignedIn)
                    .disabled(isBusy)
                Text("Stay signed in on this Mac after you quit. Takes effect at your next sign-in. Your password is never stored.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle("Require Touch ID", isOn: touchIDBinding)
                    .disabled(!keepSignedIn || !biometryAvailable || isBusy || isApplying)
                Text(touchIDHelp)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Section {
                LabeledContent("Saved sign-in") {
                    Button("Forget This Mac…", role: .destructive) {
                        confirmingForget = true
                    }
                    .disabled(isBusy)
                }
                if forgotten {
                    Label("The saved sign-in was removed from this Mac.", systemImage: "checkmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .settingsFormLayout()
        .onChange(of: keepSignedIn) { _, keep in
            // Off = nothing may stay in the Keychain (same as the login checkbox).
            if !keep { Task { await session.forgetRememberedSession() } }
        }
        .confirmationDialog(
            "Forget this Mac?",
            isPresented: $confirmingForget
        ) {
            Button("Forget This Mac", role: .destructive) {
                Task {
                    await session.forgetThisMac()
                    forgotten = true
                }
            }
        } message: {
            Text("The saved sign-in and the remembered username are removed from this Mac. You stay signed in until you sign out or quit.")
        }
    }

    /// Writes the preference only once the vault followed it; a failed
    /// switch leaves the stored value (and the toggle) as it was.
    private var touchIDBinding: Binding<Bool> {
        Binding(
            get: { requireTouchID },
            set: { required in
                guard required != requireTouchID, !isApplying else { return }
                isApplying = true
                Task {
                    let applied = await session.setRequireTouchID(required)
                    if applied { requireTouchID = required }
                    isApplying = false
                }
            }
        )
    }

    private var touchIDHelp: LocalizedStringKey {
        if !biometryAvailable {
            return "Touch ID isn’t available on this Mac right now. It needs a Touch ID sensor with an enrolled fingerprint."
        }
        if !keepSignedIn {
            return "Turn on “Keep me signed in” to protect the saved sign-in with Touch ID."
        }
        return "Ask for Touch ID before resuming the saved sign-in. Adding or removing a fingerprint removes the saved sign-in."
    }
}

#if DEBUG
#Preview("Account — Light") {
    AccountSettingsView(biometryAvailable: true)
        .environment(PreviewFixtures.session())
        .frame(width: 460)
        .preferredColorScheme(.light)
}

#Preview("Account — Dark") {
    AccountSettingsView(biometryAvailable: true)
        .environment(PreviewFixtures.session())
        .frame(width: 460)
        .preferredColorScheme(.dark)
}

#Preview("Account, No Touch ID — Light") {
    AccountSettingsView(biometryAvailable: false)
        .environment(PreviewFixtures.session())
        .frame(width: 460)
        .preferredColorScheme(.light)
}

#Preview("Account, No Touch ID — Dark") {
    AccountSettingsView(biometryAvailable: false)
        .environment(PreviewFixtures.session())
        .frame(width: 460)
        .preferredColorScheme(.dark)
}
#endif
