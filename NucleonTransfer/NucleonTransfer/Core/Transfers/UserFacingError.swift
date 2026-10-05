// Nucleon Transfer — user-facing error mapping (F6, copy rewritten F8.4-U2).
// Every network/crypto/API failure on a user path must surface in the UI
// with an ACTIONABLE message (no silent prints, no raw dumps). This mapper
// is pure (Foundation only) so it is offline-testable; view-models call it
// before assigning to status/downloadStatus/errorMessage.
//
// Copy rules (F8.4-U2): "what happened + what to do", plain language, no
// protocol jargon or enum dumps; a Proton/HTTP code, when there is one,
// goes last as "(Error N)". Typed errors are classified first; the string
// path (`message(forMessage:)`) only understands the queue's own name-free
// tokens and matches status codes on word boundaries — it is never fed
// text that carries a file name (producers keep names out of
// TransferFailure messages; rows show the name next to the message).
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
            case .cancelled:
                return "Upload stopped."
            case let .transient(msg):
                return message(forMessage: msg)
            case let .permanent(msg):
                return message(forMessage: msg)
            }
        }
        if let api = error as? ProtonAPIError {
            return message(forAPI: api)
        }
        if let dl = error as? FileDownloadError {
            return message(forDownload: dl)
        }
        if let chain = error as? DecryptChainError {
            return message(forChain: chain)
        }
        if let source = error as? UploadSourceError {
            return source == .changedDuringUpload ? changedDuringUpload : fileUnreadable
        }
        if let name = error as? FolderNameError {
            return name.message
        }
        if error is FileUploadError || isEncryptionError(error) {
            return "Something went wrong preparing this file. Try again."
        }
        if error is FolderCreateError {
            return "Something went wrong preparing the new folder. Try again; if it keeps happening, report the problem."
        }
        if error is LocalTreeScanError {
            return "Couldn't read this folder on your Mac. Check that it still exists and that you can open it, then try again."
        }
        if isDecryptionError(error) {
            return "Couldn't decrypt this item. Reload and try again; if it keeps happening, the item may be damaged."
        }
        if error is CancellationError {
            return "Cancelled."
        }
        let ns = error as NSError
        if ns.domain == (NSURLErrorDomain as String) {
            return message(forURLErrorCode: ns.code)
        }
        if ns.domain == NSCocoaErrorDomain || ns.domain == NSPOSIXErrorDomain {
            return message(forFileError: ns)
        }
        // Errors that carry their own user-facing text (e.g. the browser's
        // FolderOperationError) are echoed verbatim — never through the
        // string heuristics, since such text may quote item names.
        if error is LocalizedError, let text = (error as? LocalizedError)?.errorDescription,
           !text.isEmpty
        {
            return text
        }
        return somethingWentWrong
    }

    /// Failed upload row text (F8.4-U7b): the typed `errorCode` decides
    /// first — Proton 2000 (not allowlisted) gets the short text whatever
    /// the envelope said. Jobs persisted before `errorCode` existed (nil)
    /// fall back to the string path, which still parses "api 2000: …".
    static func message(forJob job: TransferJob) -> String {
        if job.errorCode == UploadBlockDetection.notAllowlistedCode {
            return uploadAllowlisted
        }
        return message(forMessage: job.errorMessage ?? "Upload failed")
    }

    /// Mapping for already-stringified queue messages (TransferJob.errorMessage
    /// persists as String). Understands the name-free tokens written by
    /// `TransferErrorClassify` ("api N: …", "http N: …", "rate limited"),
    /// legacy pre-F8.4 strings, and plain status codes (word-boundary
    /// match). Anything already user-facing passes through unchanged, so
    /// mapping twice is harmless.
    static func message(forMessage msg: String) -> String {
        let text = msg.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return somethingWentWrong }
        // 1. Queue tokens: "api 2000: …", "http 503: …".
        if let token = parseToken(text) {
            return token.isHTTP
                ? message(forStatus: token.code)
                : message(forCode: token.code, message: token.detail)
        }
        let lower = text.lowercased()
        // 2. Fixed internal tokens, plus legacy strings that embedded a file
        //    name — recognised by their prefix only, so the name is never
        //    looked at.
        if lower == "rate limited" { return rateLimited }
        if lower.hasPrefix("local file missing") { return fileMissing }
        if lower.hasPrefix("cannot read") { return fileUnreadable }
        if lower.contains("changed while it was uploading") { return changedDuringUpload }
        if lower.contains("nodehashkey") || lower.contains("has no root link") {
            return incompleteItemData
        }
        // 3. Already final: our own "(Error N)" suffix, or quoted names
        //    (“…”) from FolderConflictPolicy / FolderNameError copy.
        if text.range(of: #"\(Error -?\d+\)\.?$"#, options: .regularExpression) != nil
            || text.contains("“") || text.contains("\"")
        {
            return text
        }
        // 4. Name-free free text (legacy envelopes, URL descriptions):
        //    status codes on word boundaries only — "IMG_5001" ≠ 500.
        if matches(lower, #"\b2028\b"#) || lower.contains("rate limit")
            || lower.contains("too many recent logins")
        {
            return rateLimited
        }
        if matches(lower, #"\b9001\b"#) || lower.contains("human verification") {
            return humanVerification
        }
        if matches(lower, #"\b429\b"#) || lower.contains("too many requests") {
            return message(forStatus: 429)
        }
        if let code = firstMatch(lower, #"\b5\d\d\b"#) {
            return message(forStatus: code)
        }
        if lower.contains("bad server response") {
            return message(forStatus: 500)
        }
        if matches(lower, #"\b401\b"#) || lower.contains("unauthorized")
            || lower.contains("session expired") || lower.contains("not signed in")
        {
            return signedOut
        }
        if lower.contains("hashmismatch") || lower.contains("hash mismatch")
            || lower.contains("integrity check")
        {
            return integrityFailed
        }
        return text
    }

    // MARK: - shared copy

    static var rateLimited: String {
        "Too many recent sign-in attempts. Wait about 10 minutes before trying again — if you're already signed in, keep using this session. (Error 2028)"
    }

    static var humanVerification: String {
        "Proton is asking for human verification. Sign in at drive.proton.me in your browser and complete the check, then try again here. (Error 9001)"
    }

    /// Proton's block-upload endpoint (`POST /drive/blocks`) enforces a
    /// strict appversion allowlist (live-proven F6), so uploads answer 2000
    /// until this app is allowlisted. Short per-row text: the browser shows
    /// a banner with the explanation (F8.4-U1).
    static var uploadAllowlisted: String {
        "Upload not available yet (Error 2000)."
    }

    /// Name-free: the row already shows which file it is.
    static var changedDuringUpload: String {
        "This file changed while it was uploading. Try again once it's no longer being written."
    }

    static var fileMissing: String {
        "The original file is no longer on your Mac. Add it again to upload it."
    }

    static var fileUnreadable: String {
        "Couldn't read this file on your Mac. Check that it still exists and that you can open it, then add it again."
    }

    static var integrityFailed: String {
        "The download failed an integrity check, so nothing was saved. Try again."
    }

    static var signedOut: String {
        "You've been signed out. Sign in again to continue."
    }

    static var somethingWentWrong: String {
        "Something went wrong. Try again."
    }

    private static var incompleteItemData: String {
        "Proton sent incomplete encryption data for this item. Reload and try again; if it keeps happening, report the problem."
    }

    private static var unreadableServerData: String {
        "Proton sent download data this app couldn't read. Try again; if it keeps happening, report the problem."
    }

    // MARK: - typed errors

    private static func message(forAPI api: ProtonAPIError) -> String {
        switch api {
        case .rateLimited:
            return rateLimited
        case .humanVerificationRequired:
            return humanVerification
        case .needs2FA:
            return "Enter the two-factor code from your authenticator app to continue."
        case .unauthorized:
            return signedOut
        case .invalidServerProof:
            // Security-relevant: the server failed to prove it knows the
            // password verifier — treat as possible interception.
            return "Couldn't verify Proton's server, so sign-in was stopped. Your connection may be intercepted — don't sign in on this network; try again on one you trust."
        case .invalidModulusSignature:
            return "Couldn't verify the connection to Proton, so sign-in was stopped. Something on this network (a proxy, VPN or security software) may be intercepting it — don't sign in on this network; try again on one you trust."
        case .unsupportedAuthVersion:
            return "This account uses an older password format this app can't sign in with. Change your password at account.proton.me to update it, then sign in again."
        case .secureRandomFailed:
            return "Your Mac couldn't generate the secure random data needed to sign in. Try again; if it keeps happening, restart your Mac."
        case .bcryptNotAvailable:
            return "Sign-in couldn't start because part of the app is missing. Reinstall Nucleon Transfer, then try again."
        case .invalidBcryptSalt:
            return "Proton sent sign-in data this app couldn't read. Try again; if it keeps happening, report the problem."
        case .keyVerificationFailed:
            return "Couldn't unlock your account's encryption keys. Make sure your password is right and sign in again."
        case .srpParamsOutOfBounds:
            return "Proton sent sign-in data that failed a safety check. Check your network (VPN or proxy) and try again."
        case let .api(code, msg):
            return message(forCode: code, message: msg)
        case let .http(status, code, msg, _):
            // The envelope code is more specific than the status when the
            // body carried one (2028 / 9001 / 2000 ride on 4xx statuses).
            if let code, code != 1000 { return message(forCode: code, message: msg) }
            return message(forStatus: status)
        case .untrustedStorageHost:
            return "Proton sent a storage address this app doesn't trust, so nothing was sent. Try again; if it keeps happening, report the problem."
        case let .transport(underlying):
            return message(for: underlying)
        }
    }

    private static func message(forDownload error: FileDownloadError) -> String {
        switch error {
        case .hashMismatch:
            return integrityFailed
        case .badBlockHash, .blockIndexGap:
            return unreadableServerData
        case .emptyBlockList:
            return "This file has nothing to download yet — it may still be uploading. Try again in a moment."
        case .missingContentKey:
            return "Couldn't unlock this file. Sign out and back in, then try again; if it keeps happening, the file may be damaged."
        case .missingRevision:
            return "This file is no longer available — it may have been deleted. Reload the folder."
        case .unsafeDestination:
            return "Download blocked: an item's name would save files outside the folder you chose. Rename the item, then try again."
        case .manifestSignatureMissing:
            return "Download stopped: this file is not signed, so who uploaded it can't be verified. Nothing was saved."
        case .manifestSignatureInvalid:
            return "Download stopped: the file's signature couldn't be verified, so it may have been altered. Nothing was saved."
        case .manifestSignatureUnverifiable:
            return "Download stopped: the file's author couldn't be verified because it was signed by an address outside your account. Nothing was saved."
        case .contentKeySignatureInvalid:
            return "Download stopped: the file's key failed a signature check, so the file may have been tampered with. Nothing was saved."
        case .blockSignatureInvalid:
            return "Download stopped: part of the file failed a signature check, so it may have been tampered with. Nothing was saved."
        case .destinationUnavailable:
            return "Couldn't find a free file name in the folder you chose. Choose another folder and try again."
        }
    }

    /// Key-level signature failures (F8.1-S2): the key material was refused,
    /// never used. Actionable: reload; persistent → possible tampering.
    private static func message(forChain error: DecryptChainError) -> String {
        switch error {
        case .missingMaterial:
            return incompleteItemData
        case .signatureMissing:
            return "Couldn't open this item because its encryption data isn't signed. Reload and try again; if it keeps happening, the item may have been tampered with."
        case .signatureInvalid:
            return "Couldn't open this item because its signature couldn't be verified. Reload and try again; if it keeps happening, the item may have been tampered with."
        case .weakSignatureHash:
            return "Couldn't open this item because it's signed with an outdated, insecure method. Contact Proton support about this item."
        case .unknownSigner:
            return "Couldn't verify this item because it was signed by someone outside your account. Items shared by other people aren't supported yet."
        }
    }

    /// Proton envelope codes (`Code` in the JSON body). Statuses that
    /// arrive through `.api` (429, 5xx, 401) share the status wording.
    private static func message(forCode code: Int, message msg: String) -> String {
        switch code {
        case 2028: return rateLimited
        case 9001: return humanVerification
        case 2000: return uploadAllowlisted
        case 401, 429, 500...599: return message(forStatus: code)
        case 2500:
            return "An item with this name already exists here. Rename it and try again. (Error 2500)"
        case 2501:
            // Reused server-side: folder-creation signature rejects AND
            // "Draft file not found" on trash/delete (live-proven F6).
            return "Proton couldn't find or accept this item. Reload the folder and try again — if you were deleting it, it may already be gone. (Error 2501)"
        case 2511:
            return "This location doesn't accept new items. Upload to a folder in My Files instead. (Error 2511)"
        case 200501:
            return "Proton didn't accept the new folder's encryption data. Try again; if it keeps happening, report the problem. (Error 200501)"
        default:
            // Proton's envelope `Error` text is written for end users
            // ("Incorrect login credentials. Please try again.").
            let detail = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !detail.isEmpty else {
                return "Proton couldn't complete the request. Try again. (Error \(code))"
            }
            let sentence = detail.hasSuffix(".") || detail.hasSuffix("!") || detail.hasSuffix("?")
                ? detail : detail + "."
            return "\(sentence) (Error \(code))"
        }
    }

    /// HTTP statuses without a usable envelope (storage host, bad bodies).
    private static func message(forStatus status: Int) -> String {
        switch status {
        case 401:
            return signedOut
        case 429:
            return "Proton is busy right now. Transfers back off and retry on their own — leave the app open. (Error 429)"
        case 500...599:
            return "Proton's servers are having trouble. Transfers retry on their own; otherwise try again in a few minutes. (Error \(status))"
        case 404:
            return "This item is no longer available. Reload the folder and try again. (Error 404)"
        default:
            return "Proton couldn't complete the request. Try again; if it keeps happening, reload the folder. (Error \(status))"
        }
    }

    private static func message(forURLErrorCode code: Int) -> String {
        switch code {
        case NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost,
             NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost,
             NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed,
             NSURLErrorResourceUnavailable, NSURLErrorInternationalRoamingOff,
             NSURLErrorCallIsActive, NSURLErrorDataNotAllowed:
            return "Couldn't reach Proton. Check your internet connection and try again."
        case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
             NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
             NSURLErrorClientCertificateRequired:
            return "Couldn't verify Proton's server. Check your network (VPN or proxy) and try again."
        case NSURLErrorCancelled:
            return "Cancelled."
        default:
            return "A network error occurred. Check your connection and try again."
        }
    }

    /// Local file-system failures (Cocoa / POSIX). Their descriptions quote
    /// file names and paths, so they are never echoed.
    private static func message(forFileError ns: NSError) -> String {
        if ns.domain == NSCocoaErrorDomain {
            switch ns.code {
            case NSFileWriteOutOfSpaceError:
                return "There isn't enough space on your Mac. Free up some space, then try again."
            case NSFileReadNoPermissionError, NSFileWriteNoPermissionError:
                return "This app doesn't have permission to use that location. Choose another folder, then try again."
            case NSFileNoSuchFileError, NSFileReadNoSuchFileError:
                return "The file or folder is no longer there. Check that it still exists, then try again."
            default:
                break
            }
        } else if ns.code == Int(ENOSPC) {
            return "There isn't enough space on your Mac. Free up some space, then try again."
        }
        return "Couldn't read or write a file on your Mac. Check that it still exists and that there's enough space, then try again."
    }

    // MARK: - helpers

    private static func isEncryptionError(_ error: Error) -> Bool {
        error is MessageEncryptError || error is SEDEncryptError || error is ECDHEncryptError
            || error is DetachedSignError || error is NodeKeyGenError
    }

    private static func isDecryptionError(_ error: Error) -> Bool {
        error is MessageDecryptError || error is SEDError || error is ECDHDecryptError
            || error is SigError || error is PacketError || error is ArmorError
            || error is SecretKeyError || error is KeyWrapError || error is AESError
            || error is PGPHashError
    }

    private struct Token {
        var isHTTP: Bool
        var code: Int
        var detail: String
    }

    /// "api 2000: msg" / "http 503: msg" (TransferErrorClassify output).
    private static func parseToken(_ text: String) -> Token? {
        guard let match = text.wholeMatch(of: #/(api|http) (\d{1,7}): ?(.*)/#.dotMatchesNewlines()),
              let code = Int(match.2)
        else { return nil }
        return Token(isHTTP: match.1 == "http", code: code, detail: String(match.3))
    }

    private static func matches(_ text: String, _ pattern: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }

    private static func firstMatch(_ text: String, _ pattern: String) -> Int? {
        guard let range = text.range(of: pattern, options: .regularExpression) else { return nil }
        return Int(text[range])
    }
}
