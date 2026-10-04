// Nucleon Transfer — login screen (F7 S4.1, spec 6.6).
// Centered auth card: app icon + title, grouped credentials form, inline
// error (announced to VoiceOver), prominent Sign In that swaps to a
// spinner while SRP runs, then the third-party disclaimer. Credentials go
// to AppSession; the password field clears on submit — the retained copy
// lives as zeroed-after-use Data inside AppSession.pendingPassword. The
// field's own String storage cannot be wiped (Swift strings are immutable
// values); it is dropped, not zeroed.
import AppKit // NSApp.applicationIconImage — header icon
import SwiftUI

struct LoginView: View {
    @Environment(AppSession.self) private var session
    @State private var username = ""
    @State private var password = ""
    @FocusState private var focus: Field?

    private enum Field {
        case username, password
    }

    /// SRP handshake in flight: the button swaps to a spinner and disables.
    private var isSigningIn: Bool {
        session.phase == .signingIn
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 64, height: 64)
                .accessibilityHidden(true)
            Text("Nucleon Transfer")
                .font(.largeTitle.weight(.semibold))
            Text("Sign in with your Proton account")
                .foregroundStyle(.secondary)
            // Grouped Form collapsed the SecureField row once the error
            // label appeared — the spec's sanctioned fallback: plain
            // roundedBorder fields at .large.
            VStack(spacing: 8) {
                TextField(
                    "Email or username",
                    text: $username,
                    prompt: Text("Email or username")
                )
                .textContentType(.username)
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
                .focused($focus, equals: .username)
                .onSubmit { focus = .password }
                .accessibilityLabel("Email or username")
                SecureField(
                    "Password",
                    text: $password,
                    prompt: Text("Password")
                )
                .textContentType(.password)
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
                .focused($focus, equals: .password)
                .onSubmit(signIn)
                .accessibilityLabel("Password")
            }
            .frame(width: 360)
            if let error = session.loginError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
            Button(action: signIn) {
                Group {
                    if isSigningIn {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Sign In")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityLabel(isSigningIn ? "Signing In" : "Sign In")
            .disabled(username.isEmpty || password.isEmpty || isSigningIn)
            .frame(width: 360)
            Divider()
                .frame(width: 360)
            Text("Nucleon Transfer is an independent, open-source app. It is not affiliated with or endorsed by Proton AG. Your password is used only to sign in and unlock your keys on this Mac — it is never stored.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 380)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .frame(minWidth: 420, minHeight: 320)
        .task {
            // A failed 2FA lands back here with the typed username gone
            // (this view unmounted while the prompt was up) — repopulate
            // it from the session so only the password needs retyping.
            if username.isEmpty, let loginUsername = session.loginUsername {
                username = loginUsername
            }
            focus = .username
            // A 2FA failure lands back here with the error already set —
            // onChange missed it while the view was unmounted, so announce
            // it on appear too.
            announce(session.loginError)
        }
        .onChange(of: session.loginError) { _, error in
            announce(error)
        }
    }

    /// Captures the credentials and hands them to AppSession; the field
    /// copy clears up front (the retained bytes live in pendingPassword).
    private func signIn() {
        let name = username
        let pwd = password
        password = ""
        Task { await session.signIn(username: name, password: pwd) }
    }

    /// VoiceOver must hear failures — the inline label alone is easy to
    /// miss while focus sits inside a field.
    private func announce(_ message: String?) {
        guard let message else { return }
        AccessibilityNotification.Announcement(message).post()
    }
}

#if DEBUG
extension LoginView {
    /// Preview seam: seeds the username field so the "filled" states render
    /// without typing. Never ships (DEBUG only).
    init(initialUsername: String) {
        _username = State(initialValue: initialUsername)
    }
}

#Preview("Empty — Light") {
    LoginView()
        .environment(PreviewFixtures.session(phase: .signedOut))
        .preferredColorScheme(.light)
}

#Preview("Empty — Dark") {
    LoginView()
        .environment(PreviewFixtures.session(phase: .signedOut))
        .preferredColorScheme(.dark)
}

#Preview("Error — Light") {
    let session = PreviewFixtures.session(phase: .signedOut)
    session.loginError = "Incorrect login credentials. Please try again."
    return LoginView(initialUsername: "raphael")
        .environment(session)
        .preferredColorScheme(.light)
}

#Preview("Error — Dark") {
    let session = PreviewFixtures.session(phase: .signedOut)
    session.loginError = "Incorrect login credentials. Please try again."
    return LoginView(initialUsername: "raphael")
        .environment(session)
        .preferredColorScheme(.dark)
}

#Preview("Signing In — Light") {
    LoginView(initialUsername: "raphael")
        .environment(PreviewFixtures.session(phase: .signingIn))
        .preferredColorScheme(.light)
}

#Preview("Signing In — Dark") {
    LoginView(initialUsername: "raphael")
        .environment(PreviewFixtures.session(phase: .signingIn))
        .preferredColorScheme(.dark)
}
#endif
