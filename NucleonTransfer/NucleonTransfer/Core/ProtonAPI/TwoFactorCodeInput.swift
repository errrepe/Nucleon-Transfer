// Nucleon Transfer — 2FA code field rules (F8.4-U5).
// Two entry modes share Proton's single `TwoFactorCode` field of
// POST /auth/v4/2fa: the 6-digit authenticator (TOTP) code, and a one-time
// recovery code. Proton's own web login sends both through the same call —
// WebClients packages/components/containers/login/MinimalLoginContainer.tsx
// (TOTPForm: `type: 'totp' | 'recovery-code'`, whitespace stripped,
// auto-submit only for the 6-digit code) → loginActions.ts `handleTotp` →
// `auth2FA({ TwoFactorCode: totp })` (shared/lib/api/auth.ts). Pure,
// offline-testable; TwoFactorView filters every keystroke through here.
import Foundation

enum TwoFactorCodeInput {
    enum Mode: Sendable, Equatable {
        /// 6-digit code from an authenticator app.
        case authenticator
        /// One of the single-use backup codes saved at 2FA setup.
        case recoveryCode
    }

    static let authenticatorLength = 6
    /// Generous cap for a pasted recovery code (Proton's are 8 characters);
    /// only guards against pasting a whole document into the field.
    static let recoveryMaxLength = 64

    /// What the field keeps of `raw`: ASCII digits (max 6) for an
    /// authenticator code; for a recovery code everything but whitespace
    /// and control characters (the web client strips `\s+` the same way).
    static func filter(_ raw: String, mode: Mode) -> String {
        switch mode {
        case .authenticator:
            return String(raw.filter { $0.isASCII && $0.isNumber }.prefix(authenticatorLength))
        case .recoveryCode:
            let kept = raw.unicodeScalars.filter {
                !CharacterSet.whitespacesAndNewlines.contains($0)
                    && !CharacterSet.controlCharacters.contains($0)
            }
            return String(String.UnicodeScalarView(kept).prefix(recoveryMaxLength))
        }
    }

    /// Verify is enabled (and Return submits) only for a complete code.
    static func isComplete(_ code: String, mode: Mode) -> Bool {
        switch mode {
        case .authenticator:
            return code.count == authenticatorLength && code.allSatisfy { $0.isASCII && $0.isNumber }
        case .recoveryCode:
            return !filter(code, mode: .recoveryCode).isEmpty
        }
    }

    /// The authenticator code sends itself at 6 digits; a recovery code has
    /// no fixed length, so it waits for Return / Verify.
    static func shouldAutoSubmit(_ code: String, mode: Mode) -> Bool {
        mode == .authenticator && isComplete(code, mode: mode)
    }
}
