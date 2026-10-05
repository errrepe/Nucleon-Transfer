// Nucleon Transfer — login screen (F7 S4.1, spec 6.6).
// Centered auth card: app icon + title, grouped credentials form, inline
// error (announced to VoiceOver), prominent Sign In that swaps to a
// "Signing in…" spinner while SRP + bcrypt run (fields locked meanwhile),
// links to Proton's password-reset and sign-up pages, then the
// third-party disclaimer. A failed attempt refocuses the (already
// cleared) password field (F8.4-U5). Credentials go
// to AppSession; the password field clears on submit — the retained copy
// lives as zeroed-after-use Data inside AppSession.pendingPassword. The
// field's own String storage cannot be wiped (Swift strings are immutable
// values); it is dropped, not zeroed.
// F8.5: "Keep me signed in" checkbox (default off, @AppStorage; turning it
// off deletes any remembered session), the username prefilled from the
// last successful sign-in, and a Try Again button when a remembered
// session couldn't be restored for lack of network.
// F8.5-V3: a "Use Touch ID" button when the Touch ID prompt for a sealed
// remembered session was cancelled (or unavailable) — the session is kept.
import AppKit // NSApp.applicationIconImage — header icon
import SwiftUI

struct LoginView: View {
    @Environment(AppSession.self) private var session
    @AppStorage(AppSettings.keepSignedInKey)
    private var keepSignedIn = AppSettings.defaultKeepSignedIn
    @AppStorage(AppSettings.lastUsernameKey)
    private var lastUsername = ""
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

    private var trimmedUsername: String {
        username.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Return and Sign In only act on a complete form (F8.4-U5): Return in
    /// the password field with no username must not start an SRP round.
    private var canSubmit: Bool {
        !trimmedUsername.isEmpty && !password.isEmpty && !isSigningIn
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
                .disabled(isSigningIn)
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
                .disabled(isSigningIn)
                .onSubmit(signIn)
                .accessibilityLabel("Password")
                Toggle("Keep me signed in", isOn: $keepSignedIn)
                    .toggleStyle(.checkbox)
                    .disabled(isSigningIn)
                    .help("Stay signed in on this Mac after you quit. Your password is never stored.")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(width: 360)
            if let error = session.loginError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
            if session.canRetryRestore {
                // The remembered session survived a network failure:
                // retry it without the password.
                Button("Try Again") {
                    Task { await session.restoreRememberedSession() }
                }
                .disabled(isSigningIn)
            }
            if session.canRetryTouchID {
                Button {
                    Task { await session.restoreRememberedSession() }
                } label: {
                    Label("Use Touch ID", systemImage: "touchid")
                }
                .disabled(isSigningIn)
            }
            Button(action: signIn) {
                Group {
                    if isSigningIn {
                        HStack(spacing: 6) {
                            ProgressView()
                                .controlSize(.small)
                            Text("Signing in…")
                        }
                    } else {
                        Text("Sign In")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityLabel(isSigningIn ? Text("Signing in…") : Text("Sign In"))
            .disabled(!canSubmit)
            .frame(width: 360)
            HStack(spacing: 16) {
                if let url = AccountLinks.resetPassword {
                    Link("Forgot password?", destination: url)
                }
                if let url = AccountLinks.createAccount {
                    Link("Create account", destination: url)
                }
            }
            .font(.callout)
            Divider()
                .frame(width: 360)
            Text("Nucleon Transfer is an independent, open-source app. It is not affiliated with or endorsed by Proton AG. Your password is used only to sign in and unlock your keys on this Mac — it is never stored. “Keep me signed in” saves a session token in this Mac's keychain.")
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
            // Otherwise (F8.5) the last account that signed in on this Mac.
            if username.isEmpty {
                username = session.loginUsername ?? lastUsername
            }
            // A prefilled username (failed 2FA/unlock, or a previous
            // sign-in): the password is what needs typing.
            focus = username.isEmpty ? .username : .password
            // A 2FA failure lands back here with the error already set —
            // onChange missed it while the view was unmounted, so announce
            // it on appear too.
            announce(session.loginError)
        }
        .onChange(of: session.loginError) { _, error in
            announce(error)
            if error != nil, !isSigningIn { focus = .password }
        }
        .onChange(of: keepSignedIn) { _, keep in
            // Off = nothing may stay in the Keychain (F8.5).
            if !keep { Task { await session.forgetRememberedSession() } }
        }
        .onChange(of: isSigningIn) { _, signingIn in
            // The fields were disabled during SRP; after a failure the
            // (already cleared) password field gets focus back.
            if !signingIn, session.loginError != nil { focus = .password }
        }
    }

    /// Captures the credentials and hands them to AppSession; the field
    /// copy clears up front (the retained bytes live in pendingPassword).
    private func signIn() {
        guard canSubmit else {
            // Return in the password field with no username: go fill it.
            if trimmedUsername.isEmpty, !isSigningIn { focus = .username }
            return
        }
        let name = trimmedUsername
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

#Preview("Restore Offline — Light") {
    let session = AppSession.preview(phase: .signedOut, canRetryRestore: true)
    session.loginError = RestoreFailure.message(for: .keepAndRetry)
    return LoginView(initialUsername: "raphael")
        .environment(session)
        .preferredColorScheme(.light)
}

#Preview("Touch ID Cancelled — Light") {
    let session = AppSession.preview(phase: .signedOut, canRetryTouchID: true)
    session.loginError = RestoreFailure.message(for: .retryTouchID)
    return LoginView(initialUsername: "raphael")
        .environment(session)
        .preferredColorScheme(.light)
}

#Preview("Touch ID Cancelled — Dark") {
    let session = AppSession.preview(phase: .signedOut, canRetryTouchID: true)
    session.loginError = RestoreFailure.message(for: .retryTouchID)
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
