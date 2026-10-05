// Nucleon Transfer — TOTP prompt (F7 S4.1, F8.2-R7).
// Shown while AppSession.phase == .needsTwoFactor: a six-digit code field
// (digits only, auto-submits at 6). Verification runs in place — an inline
// "Verifying…" spinner, field and buttons disabled — and a rejected code
// stays here with an inline error (announced to VoiceOver like LoginView),
// the field cleared and refocused. Back (or Esc) cancels the whole sign-in
// and lands on the login screen. F8.4-U5: "Use a recovery code instead"
// relaxes the field to a free-form single-use backup code (same Proton
// field — see TwoFactorCodeInput), submitted with Return / Verify.
import SwiftUI

struct TwoFactorView: View {
    @Environment(AppSession.self) private var session
    @State private var code = ""
    @State private var mode: TwoFactorCodeInput.Mode = .authenticator
    @FocusState private var codeFocused: Bool

    private var isVerifying: Bool { session.isVerifyingTwoFactor }
    private var isRecovery: Bool { mode == .recoveryCode }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Two-Factor Authentication")
                .font(.title2.weight(.semibold))
            Group {
                if isRecovery {
                    Text("Enter one of the recovery codes you saved when you turned on two-factor authentication. Each code works only once.")
                } else {
                    Text("Enter the 6-digit code from your authenticator app.")
                }
            }
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: 360)
            TextField(
                isRecovery ? "Recovery code" : "Authentication code",
                text: $code,
                prompt: Text(isRecovery ? "Recovery code" : "123456")
            )
            .textContentType(isRecovery ? nil : .oneTimeCode)
            .autocorrectionDisabled()
            .textFieldStyle(.roundedBorder)
            .font(.title2.monospacedDigit())
            .multilineTextAlignment(.center)
            .frame(width: isRecovery ? 260 : 180)
            .focused($codeFocused)
            .disabled(isVerifying)
            .onChange(of: code) { _, newValue in
                // Authenticator: digits only, six max — then the code sends
                // itself. Recovery: no whitespace, sent with Return/Verify.
                let filtered = TwoFactorCodeInput.filter(newValue, mode: mode)
                if filtered != newValue { code = filtered }
                if TwoFactorCodeInput.shouldAutoSubmit(code, mode: mode) { verify() }
            }
            .onSubmit(verify)
            .accessibilityLabel(isRecovery ? "Recovery code" : "Authentication code")
            if isVerifying {
                HStack(spacing: 6) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Verifying…")
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Verifying code…")
            } else if let error = session.twoFactorError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
            HStack(spacing: 12) {
                Button("Back") {
                    Task { await session.cancelTwoFactor() }
                }
                .keyboardShortcut(.cancelAction)
                .disabled(isVerifying)
                Button("Verify", action: verify)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!TwoFactorCodeInput.isComplete(code, mode: mode) || isVerifying)
            }
            Button(isRecovery ? "Use authenticator code instead" : "Use a recovery code instead") {
                switchMode()
            }
            .buttonStyle(.link)
            .font(.callout)
            .disabled(isVerifying)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(minWidth: 420, minHeight: 320)
        .task { codeFocused = true }
        .onChange(of: session.twoFactorError) { _, error in
            guard let error else { return }
            // A rejected code: start over in place.
            code = ""
            codeFocused = true
            AccessibilityNotification.Announcement(error).post()
        }
        .onChange(of: isVerifying) { _, verifying in
            // The field was disabled while verifying; give focus back.
            if !verifying { codeFocused = true }
        }
    }

    /// Submits the code once it is complete — AppSession verifies it in
    /// place and only flips the phase to .unlocking once Proton accepts it.
    private func verify() {
        guard TwoFactorCodeInput.isComplete(code, mode: mode), !isVerifying else { return }
        let submitted = code
        let submittedMode = mode
        Task { await session.submitTwoFactor(code: submitted, mode: submittedMode) }
    }

    /// Authenticator ⇄ recovery code: start the new mode with an empty
    /// field and no stale error, focus kept in the field.
    private func switchMode() {
        guard !isVerifying else { return }
        mode = isRecovery ? .authenticator : .recoveryCode
        code = ""
        session.clearTwoFactorError()
        codeFocused = true
    }
}

#if DEBUG
extension TwoFactorView {
    /// Preview seam: opens in the given mode. Never ships (DEBUG only).
    init(initialMode: TwoFactorCodeInput.Mode) {
        _mode = State(initialValue: initialMode)
    }
}

#Preview("Light") {
    TwoFactorView()
        .environment(PreviewFixtures.session(phase: .needsTwoFactor))
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    TwoFactorView()
        .environment(PreviewFixtures.session(phase: .needsTwoFactor))
        .preferredColorScheme(.dark)
}

#Preview("Recovery Code") {
    TwoFactorView(initialMode: .recoveryCode)
        .environment(PreviewFixtures.session(phase: .needsTwoFactor))
}

#Preview("Wrong Code") {
    TwoFactorView()
        .environment(AppSession.preview(
            phase: .needsTwoFactor,
            twoFactorError: "That code didn’t work. Check your authenticator app and try again."
        ))
}
#endif
