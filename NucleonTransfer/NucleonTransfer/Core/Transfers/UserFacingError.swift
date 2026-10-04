// Nucleon Transfer — user-facing error mapping (F6).
// Every network/crypto/API failure on a user path must surface in the UI
// with an ACTIONABLE message (no silent prints, no raw dumps). This mapper
// is pure (Foundation only) so it is offline-testable; view-models call it
// before assigning to status/downloadStatus/errorMessage.
//
// Rate-limit (2028) guidance: NEVER auto-retry logins in a loop — tell the
// user to wait ~10 minutes and to keep using the current session instead of
// logging in again (AUTH.md §1 step 5e, TRANSFERS.md retry policy).

import Foundation

enum UserFacingError: Sendable {
    /// Actionable one-liner for any error reaching the UI.
    static func message(for error: Error) -> String {
        if let f = error as? TransferFailure {
            switch f {
            case .needsHumanVerification:
                return humanVerification
            case let .transient(msg):
                return message(forMessage: msg)
            case let .permanent(msg):
                return message(forMessage: msg)
            }
        }
        if let api = error as? ProtonAPIError {
            switch api {
            case .rateLimited:
                return rateLimited
            case .humanVerificationRequired:
                return humanVerification
            case .needs2FA:
                return "Two-factor code required. Enter your 6-digit TOTP to continue."
            case .unauthorized:
                return "Session expired or not signed in. Sign in again."
            case .invalidServerProof:
                return "Server proof mismatch — possible downgrade attack. Aborted. Do not retry blindly; check your connection and sign in again."
            case .invalidModulusSignature:
                return "Login setup data was invalid. Check your connection and retry once."
            case .bcryptNotAvailable:
                return "Crypto backend missing (bcrypt). Report this bug — do not retry."
            case .invalidBcryptSalt:
                return "Login data malformed. Retry once; if it persists, report this bug."
            case .keyVerificationFailed:
                return "Unlocked key does not match its public key. Wrong password or corrupted key — retry carefully."
            case let .srpParamsOutOfBounds(msg):
                return "Login setup failed (\(msg)). Check connection and retry once."
            case let .api(code, msg):
                return message(forCode: code, message: msg)
            case let .http(status, _, msg):
                // HTTP status drives the guidance (429 / 5xx / 401 share the
                // envelope-code wording).
                return message(forCode: status, message: msg)
            case let .untrustedStorageHost(host):
                return "Proton returned a storage address on an unexpected host (\(host)). Nothing was sent. Retry; if it persists, report this bug."
            case let .transport(underlying):
                return message(for: underlying)
            }
        }
        if let dl = error as? FileDownloadError {
            switch dl {
            case let .hashMismatch(index):
                return "Download failed integrity check (block \(index)). Retry the download; if it persists, the remote file may need re-upload."
            case let .badBlockHash(hash):
                return "Server returned a bad block hash (\(hash.prefix(12))…). Retry; if it persists, report this bug."
            case .blockIndexGap:
                return "Server returned a non-contiguous block list. Retry; if it persists, report this bug."
            case .emptyBlockList:
                return "Server returned no download blocks. The file may be empty or still uploading — retry in a moment."
            case .missingContentKey:
                return "Could not open the file key. The file may belong to another key or be corrupted — try again after re-login."
            case .missingRevision:
                return "No file revision found. The file may have been deleted — reload the browser."
            }
        }
        if let upload = error as? FileUploadError {
            return "Upload preparation failed (\(upload)). Re-add the file and retry."
        }
        if let folder = error as? FolderCreateError {
            return "Folder preparation failed (\(folder)). Retry; if it persists, report this bug."
        }
        let ns = error as NSError
        if ns.domain == (NSURLErrorDomain as String) {
            return message(forURLErrorCode: ns.code, description: ns.localizedDescription)
        }
        // Crypto PGP errors and anything else: never raw dump, always actionable.
        let desc = error.localizedDescription
        if desc.isEmpty {
            return "Something went wrong. Retry once; if it persists, reload and try again."
        }
        return message(forMessage: desc)
    }

    /// Heuristic mapping for already-stringified queue messages
    /// (TransferJob.errorMessage persists as String). Detects known codes
    /// and upgrades them to actionable guidance; unknown strings pass
    /// through with a retry hint.
    static func message(forMessage msg: String) -> String {
        let lower = msg.lowercased()
        if lower.contains("2028") || lower.contains("rate limit") || lower.contains("rate-limit")
            || lower.contains("too many recent logins")
        {
            return rateLimited
        }
        if lower.contains("9001") || lower.contains("human verification") {
            return humanVerification
        }
        if lower.contains("429") || lower.contains("too many requests") {
            return "Server busy (429). Backing off automatically — leave the queue running."
        }
        if lower.contains("500") || lower.contains("502") || lower.contains("503")
            || lower.contains("504") || lower.contains("bad server response")
        {
            return "Proton server error (\(msg)). Will retry automatically; if it persists, wait a few minutes."
        }
        if lower.contains("401") || lower.contains("unauthorized")
            || lower.contains("session expired") || lower.contains("not signed in")
        {
            return "Session expired or not signed in. Sign in again."
        }
        if lower.contains("2511") || lower.contains("photo") {
            return "Photo-type shares reject creation (2511). Upload to a Drive share instead."
        }
        if lower.contains("2000") && lower.contains("outdated") {
            return uploadAllowlisted
        }
        if lower.contains("hashmismatch") || lower.contains("hash mismatch")
            || lower.contains("integrity check")
        {
            return "Download failed integrity check. Retry the download; if it persists, the remote file may need re-upload."
        }
        if lower.contains("re-add") || lower.contains("local file missing")
        {
            return msg + " — re-add the folder/file to the queue."
        }
        if lower.contains("cannot read") || lower.contains("no such file") {
            return msg + " — check the local file still exists, then re-add it."
        }
        return msg
    }

    // MARK: - pieces

    static var rateLimited: String {
        "Too many recent logins (Proton 2028 rate-limit). Wait ~10 minutes before retrying — do not log in repeatedly. If you are signed in, keep using this session."
    }

    static var humanVerification: String {
        "Proton requires human verification (9001). Open drive.proton.me, complete the check, then retry. The queue is paused."
    }

    /// Proton's block-upload endpoint (`POST /drive/blocks`) enforces a
    /// strict appversion allowlist (live-proven F6: our string AND an honest
    /// high-version variant both return 2000; only the rclone string passes —
    /// no spoofing, so uploads stay disabled in this alpha). Downloads via
    /// the storage host DO accept our header (HTTP 200 live-proven).
    static var uploadAllowlisted: String {
        "Upload blocked by Proton (2000: app version not allowlisted for block upload). Our honest appversion is not yet accepted — direct-API uploads stay disabled in this alpha. Downloads work normally; the file roundtrip is validated via the rclone reference."
    }

    private static func message(forCode code: Int, message msg: String) -> String {
        if code == 2028 { return rateLimited }
        if code == 9001 { return humanVerification }
        if code == 429 {
            return "Server busy (429). Backing off automatically — leave the queue running."
        }
        if (500...599).contains(code) {
            return "Proton server error (\(code)). Will retry automatically; if it persists, wait a few minutes."
        }
        if code == 401 { return "Session expired or not signed in. Sign in again." }
        if code == 2000 { return uploadAllowlisted }
        if code == 2511 {
            return "Photo-type shares reject creation (2511). Upload to a Drive share instead."
        }
        if code == 2501 {
            // 2501 is reused server-side: folder-creation signature rejects AND
            // "Draft file not found" on trash/delete of drafts/trashed items
            // (live-proven F6) — so echo the server text instead of guessing.
            return "Proton API 2501: \(msg). Reload and retry; on delete, the item may already be trashed or deleted."
        }
        if code == 200501 {
            return "Proton rejected the folder key material (200501). Retry; if it persists, report this bug."
        }
        return "Proton API \(code): \(msg). If it repeats, reload and retry."
    }

    private static func message(forURLErrorCode code: Int, description desc: String) -> String {
        switch code {
        case NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost,
             NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost,
             NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed,
             NSURLErrorResourceUnavailable, NSURLErrorInternationalRoamingOff,
             NSURLErrorCallIsActive, NSURLErrorDataNotAllowed:
            return "Network issue (\(desc)). Check your connection — will retry automatically."
        case NSURLErrorCancelled:
            return "Cancelled."
        default:
            return "Network error (\(desc)). Retry; if it persists, check your connection."
        }
    }
}
