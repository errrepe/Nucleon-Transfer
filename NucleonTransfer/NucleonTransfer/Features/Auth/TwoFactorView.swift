// Nucleon Transfer — TOTP prompt (F7 S4.1, F8.2-R7).
// Shown while AppSession.phase == .needsTwoFactor: a six-digit code field
// (digits only, auto-submits at 6). Verification runs in place — an inline
// "Verifying…" spinner, field and buttons disabled — and a rejected code
// stays here with an inline error (announced to VoiceOver like LoginView),
// the field cleared and refocused. Back (or Esc) cancels the whole sign-in
// and lands on the login screen.
import SwiftUI

struct TwoFactorView: View {
    @Environment(AppSession.self) private var session
    @State private var code = ""
    @FocusState private var codeFocused: Bool

    private var isVerifying: Bool { session.isVerifyingTwoFactor }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)
            Text("Two-Factor Authentication")
                .font(.title2.weight(.semibold))
            Text("Enter the 6-digit code from your authenticator app.")
                .foregroundStyle(.secondary)
            TextField(
                "Authentication code",
                text: $code,
                prompt: Text("123456")
            )
            .textContentType(.oneTimeCode)
            .textFieldStyle(.roundedBorder)
            .font(.title2.monospacedDigit())
            .multilineTextAlignment(.center)
            .frame(width: 180)
            .focused($codeFocused)
            .disabled(isVerifying)
            .onChange(of: code) { _, newValue in
                // Digits only, six max — then the code sends itself.
                let filtered = String(newValue.filter(\.isNumber).prefix(6))
                if filtered != newValue { code = filtered }
                if code.count == 6 { verify() }
            }
            .onSubmit(verify)
            .accessibilityLabel("Authentication code")
            if isVerifying {
                HStack(spacing: 6) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Verifying…")
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
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
                    .disabled(code.count != 6 || isVerifying)
            }
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
        guard code.count == 6, !isVerifying else { return }
        let submitted = code
        Task { await session.submitTwoFactor(code: submitted) }
    }
}

#if DEBUG
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

#Preview("Wrong Code") {
    TwoFactorView()
        .environment(AppSession.preview(
            phase: .needsTwoFactor,
            twoFactorError: "That code didn’t work. Check your authenticator app and try again."
        ))
}
#endif
