// Nucleon Transfer — 2FA submit failure policy (F8.2-R7).
// A wrong TOTP code must keep the user on the code prompt (session and
// retained password intact) — bouncing them to the password screen forces
// a fresh login, which quickly trips Proton's 2028 login rate limit.
// Only failures that end the half-open session are unrecoverable: the
// session is gone (401), Proton rate-limits (2028 / HTTP 429) or demands
// human verification (which this app can't complete). Pure, offline-testable.
import Foundation

enum TwoFactorFailure: Sendable {
    /// True when the user can simply try another code on the same prompt.
    static func isRecoverable(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let api = error as? ProtonAPIError {
            switch api {
            case .unauthorized, .rateLimited, .humanVerificationRequired:
                return false
            case .needs2FA, .api, .transport:
                // `.api`: Proton's envelope answer to a wrong/expired code.
                return true
            case let .http(status, code, _, _):
                if status == 401 || status == 429 || code == 2028 || code == 9001 { return false }
                return true
            default:
                return false
            }
        }
        // Raw URLSession failures (offline, timeout): retryable in place.
        return (error as NSError).domain == (NSURLErrorDomain as String)
    }

    /// Inline message for the code prompt. A Proton API rejection reads as
    /// a wrong code (worded for the mode in use); everything else goes
    /// through UserFacingError.
    static func message(for error: Error, mode: TwoFactorCodeInput.Mode = .authenticator) -> String {
        if isRejectedCode(error) {
            switch mode {
            case .authenticator:
                return String(localized: "That code didn’t work. Check your authenticator app and try again.")
            case .recoveryCode:
                return String(localized: "That recovery code didn’t work. Check it and try again — each code works only once.")
            }
        }
        return UserFacingError.message(for: error)
    }

    private static func isRejectedCode(_ error: Error) -> Bool {
        if case .api? = error as? ProtonAPIError { return true }
        if case let .http(status, _, _, _)? = error as? ProtonAPIError,
           (400..<500).contains(status), status != 408
        {
            return true
        }
        return false
    }
}
