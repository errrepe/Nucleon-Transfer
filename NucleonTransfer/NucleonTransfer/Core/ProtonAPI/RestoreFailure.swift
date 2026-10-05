// Nucleon Transfer — "Keep me signed in" restore failure policy (F8.5-V2).
// When resuming a remembered session fails, the app must decide whether
// the Keychain item is still worth keeping:
// - transient (no network, timeout, 408/429/5xx, Proton rate limit,
//   cancellation): the refresh token may still be valid — KEEP the item,
//   show "Couldn't reach Proton…" with a Retry button that re-runs restore;
// - anything else (401, refresh token rejected, key unlock / signature
//   failure, malformed answer): the blob is dead or untrustworthy — DELETE
//   it and fall back to the password login with a calm "sign in again".
// Biased toward deleting: an unknown error never leaves a secret behind.
// Pure, offline-testable.
import Foundation

enum RestoreFailure: Sendable {
    enum Decision: Sendable, Equatable {
        /// Keep the remembered session; offer Retry.
        case keepAndRetry
        /// Delete the remembered session; ask for the password.
        case forget
    }

    static func decision(for error: Error) -> Decision {
        isTransient(error) ? .keepAndRetry : .forget
    }

    static func isTransient(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if error is URLError { return true }
        if let api = error as? ProtonAPIError {
            switch api {
            case .rateLimited:
                return true
            case let .transport(inner):
                return inner is URLError || inner is CancellationError
                    || (inner as NSError).domain == (NSURLErrorDomain as String)
            case let .http(status, code, _, _):
                // 9001 (human verification) can't be completed here.
                return code != 9001 && APIClient.isRetryableStatus(status)
            default:
                return false
            }
        }
        return (error as NSError).domain == (NSURLErrorDomain as String)
    }

    /// Login-screen copy for each decision.
    static func message(for decision: Decision) -> String {
        switch decision {
        case .keepAndRetry:
            return String(localized: "Couldn't reach Proton. Check your internet connection and try again.")
        case .forget:
            return String(localized: "Your saved sign-in has expired. Please sign in again.")
        }
    }
}
