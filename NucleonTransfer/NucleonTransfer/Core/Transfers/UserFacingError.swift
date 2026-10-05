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
// Persisted vs displayed (F8.4 review): TransferJob.errorMessage outlives
// the process (and a language switch), so the queue stores a stable,
// language-neutral, name-free TOKEN (`token(for:)`: "api N: …", "http N:
// …", "copy <id>", or one of the fixed file tokens) and the copy is
// localized only at display time (`message(forJob:)` / `message(for:)`).
// Messages persisted by older builds as final copy still pass through.
//
// Rate-limit (2028) guidance: NEVER auto-retry logins in a loop — tell the
// user to wait ~10 minutes and to keep using the current session instead of
// logging in again (AUTH.md §1 step 5e, TRANSFERS.md retry policy).

import Foundation

enum UserFacingError: Sendable {
    /// Fixed, name-free copy with a stable language-neutral identifier
    /// (the raw value). `token` is what the queue persists; `text` is the
    /// localized sentence, resolved at display time.
    enum Copy: String, CaseIterable, Sendable {
        case uploadStopped = "upload-stopped"
        case cancelled = "cancelled"
        case somethingWentWrong = "something-went-wrong"
        case preparingFile = "preparing-file"
        case preparingFolder = "preparing-folder"
        case folderUnreadable = "folder-unreadable"
        case decryptFailed = "decrypt-failed"
        case rateLimited = "rate-limited"
        case humanVerification = "human-verification"
        case uploadAllowlisted = "upload-allowlisted"
        case changedDuringUpload = "changed-during-upload"
        case fileMissing = "file-missing"
        case fileUnreadable = "file-unreadable"
        case folderNameTakenByFile = "folder-name-taken-by-file"
        case folderConflictUnidentified = "folder-conflict-unidentified"
        case integrityFailed = "integrity-failed"
        case signedOut = "signed-out"
        case incompleteItemData = "incomplete-item-data"
        case unreadableServerData = "unreadable-server-data"
        case needsTwoFactor = "needs-2fa"
        case serverProofInvalid = "server-proof-invalid"
        case modulusSignatureInvalid = "modulus-signature-invalid"
        case unsupportedAuthVersion = "unsupported-auth-version"
        case secureRandomFailed = "secure-random-failed"
        case bcryptNotAvailable = "bcrypt-not-available"
        case invalidBcryptSalt = "invalid-bcrypt-salt"
        case keyVerificationFailed = "key-verification-failed"
        case srpParamsOutOfBounds = "srp-params-out-of-bounds"
        case untrustedStorageHost = "untrusted-storage-host"
        case emptyBlockList = "empty-block-list"
        case missingContentKey = "missing-content-key"
        case missingRevision = "missing-revision"
        case unsafeDestination = "unsafe-destination"
        case manifestSignatureMissing = "manifest-signature-missing"
        case manifestSignatureInvalid = "manifest-signature-invalid"
        case manifestSignatureUnverifiable = "manifest-signature-unverifiable"
        case contentKeySignatureInvalid = "content-key-signature-invalid"
        case blockSignatureInvalid = "block-signature-invalid"
        case destinationUnavailable = "destination-unavailable"
        case chainSignatureMissing = "chain-signature-missing"
        case chainSignatureInvalid = "chain-signature-invalid"
        case weakSignatureHash = "weak-signature-hash"
        case unknownSigner = "unknown-signer"
        case networkUnreachable = "network-unreachable"
        case serverUnverified = "server-unverified"
        case networkError = "network-error"
        case outOfSpace = "out-of-space"
        case noPermission = "no-permission"
        case fileGone = "file-gone"
        case fileReadWrite = "file-read-write"

        /// Persisted form. The three local-file failures keep the tokens
        /// older builds already wrote (and `message(forMessage:)` matched
        /// by prefix); everything else is "copy <id>".
        var token: String {
            switch self {
            case .fileMissing: return "local file missing"
            case .fileUnreadable: return "cannot read"
            case .changedDuringUpload: return "changed while it was uploading"
            default: return Self.prefix + rawValue
            }
        }

        static let prefix = "copy "

        /// "copy <id>" → the copy; nil for any other text.
        init?(token: String) {
            guard token.hasPrefix(Self.prefix),
                  let copy = Copy(rawValue: String(token.dropFirst(Self.prefix.count)))
            else { return nil }
            self = copy
        }

        var text: String {
            switch self {
            case .uploadStopped:
                return String(localized: "Upload stopped.")
            case .cancelled:
                return String(localized: "Cancelled.")
            case .somethingWentWrong:
                return String(localized: "Something went wrong. Try again.")
            case .preparingFile:
                return String(localized: "Something went wrong preparing this file. Try again.")
            case .preparingFolder:
                return String(localized: "Something went wrong preparing the new folder. Try again; if it keeps happening, report the problem.")
            case .folderUnreadable:
                return String(localized: "Couldn't read this folder on your Mac. Check that it still exists and that you can open it, then try again.")
            case .decryptFailed:
                return String(localized: "Couldn't decrypt this item. Reload and try again; if it keeps happening, the item may be damaged.")
            case .rateLimited:
                return String(localized: "Too many recent sign-in attempts. Wait about 10 minutes before trying again — if you're already signed in, keep using this session. (Error 2028)")
            case .humanVerification:
                return String(localized: "Proton is asking for human verification. Sign in at drive.proton.me in your browser and complete the check, then try again here. (Error 9001)")
            case .uploadAllowlisted:
                // Proton's block-upload endpoint (`POST /drive/blocks`)
                // enforces a strict appversion allowlist (live-proven F6),
                // so uploads answer 2000 until this app is allowlisted.
                // Short per-row text: the browser shows a banner with the
                // explanation (F8.4-U1).
                return String(localized: "Upload not available yet (Error 2000).")
            case .changedDuringUpload:
                return String(localized: "This file changed while it was uploading. Try again once it's no longer being written.")
            case .fileMissing:
                return String(localized: "The original file is no longer on your Mac. Add it again to upload it.")
            case .fileUnreadable:
                return String(localized: "Couldn't read this file on your Mac. Check that it still exists and that you can open it, then add it again.")
            case .folderNameTakenByFile:
                return String(localized: "A file with this name already exists here, so the folder can’t be created. Rename one of them and try again.")
            case .folderConflictUnidentified:
                return String(localized: "An item with this name already exists here, but it couldn’t be identified. Reload the folder and try again.")
            case .integrityFailed:
                return String(localized: "The download failed an integrity check, so nothing was saved. Try again.")
            case .signedOut:
                return String(localized: "You've been signed out. Sign in again to continue.")
            case .incompleteItemData:
                return String(localized: "Proton sent incomplete encryption data for this item. Reload and try again; if it keeps happening, report the problem.")
            case .unreadableServerData:
                return String(localized: "Proton sent download data this app couldn't read. Try again; if it keeps happening, report the problem.")
            case .needsTwoFactor:
                return String(localized: "Enter the two-factor code from your authenticator app to continue.")
            case .serverProofInvalid:
                // Security-relevant: the server failed to prove it knows the
                // password verifier — treat as possible interception.
                return String(localized: "Couldn't verify Proton's server, so sign-in was stopped. Your connection may be intercepted — don't sign in on this network; try again on one you trust.")
            case .modulusSignatureInvalid:
                return String(localized: "Couldn't verify the connection to Proton, so sign-in was stopped. Something on this network (a proxy, VPN or security software) may be intercepting it — don't sign in on this network; try again on one you trust.")
            case .unsupportedAuthVersion:
                return String(localized: "This account uses an older password format this app can't sign in with. Change your password at account.proton.me to update it, then sign in again.")
            case .secureRandomFailed:
                return String(localized: "Your Mac couldn't generate the secure random data needed to sign in. Try again; if it keeps happening, restart your Mac.")
            case .bcryptNotAvailable:
                return String(localized: "Sign-in couldn't start because part of the app is missing. Reinstall Nucleon Transfer, then try again.")
            case .invalidBcryptSalt:
                return String(localized: "Proton sent sign-in data this app couldn't read. Try again; if it keeps happening, report the problem.")
            case .keyVerificationFailed:
                return String(localized: "Couldn't unlock your account's encryption keys. Make sure your password is right and sign in again.")
            case .srpParamsOutOfBounds:
                return String(localized: "Proton sent sign-in data that failed a safety check. Check your network (VPN or proxy) and try again.")
            case .untrustedStorageHost:
                return String(localized: "Proton sent a storage address this app doesn't trust, so nothing was sent. Try again; if it keeps happening, report the problem.")
            case .emptyBlockList:
                return String(localized: "This file has nothing to download yet — it may still be uploading. Try again in a moment.")
            case .missingContentKey:
                return String(localized: "Couldn't unlock this file. Sign out and back in, then try again; if it keeps happening, the file may be damaged.")
            case .missingRevision:
                return String(localized: "This file is no longer available — it may have been deleted. Reload the folder.")
            case .unsafeDestination:
                return String(localized: "Download blocked: an item's name would save files outside the folder you chose. Rename the item, then try again.")
            case .manifestSignatureMissing:
                return String(localized: "Download stopped: this file is not signed, so who uploaded it can't be verified. Nothing was saved.")
            case .manifestSignatureInvalid:
                return String(localized: "Download stopped: the file's signature couldn't be verified, so it may have been altered. Nothing was saved.")
            case .manifestSignatureUnverifiable:
                return String(localized: "Download stopped: the file's author couldn't be verified because it was signed by an address outside your account. Nothing was saved.")
            case .contentKeySignatureInvalid:
                return String(localized: "Download stopped: the file's key failed a signature check, so the file may have been tampered with. Nothing was saved.")
            case .blockSignatureInvalid:
                return String(localized: "Download stopped: part of the file failed a signature check, so it may have been tampered with. Nothing was saved.")
            case .destinationUnavailable:
                return String(localized: "Couldn't find a free file name in the folder you chose. Choose another folder and try again.")
            case .chainSignatureMissing:
                return String(localized: "Couldn't open this item because its encryption data isn't signed. Reload and try again; if it keeps happening, the item may have been tampered with.")
            case .chainSignatureInvalid:
                return String(localized: "Couldn't open this item because its signature couldn't be verified. Reload and try again; if it keeps happening, the item may have been tampered with.")
            case .weakSignatureHash:
                return String(localized: "Couldn't open this item because it's signed with an outdated, insecure method. Contact Proton support about this item.")
            case .unknownSigner:
                return String(localized: "Couldn't verify this item because it was signed by someone outside your account. Items shared by other people aren't supported yet.")
            case .networkUnreachable:
                return String(localized: "Couldn't reach Proton. Check your internet connection and try again.")
            case .serverUnverified:
                return String(localized: "Couldn't verify Proton's server. Check your network (VPN or proxy) and try again.")
            case .networkError:
                return String(localized: "A network error occurred. Check your connection and try again.")
            case .outOfSpace:
                return String(localized: "There isn't enough space on your Mac. Free up some space, then try again.")
            case .noPermission:
                return String(localized: "This app doesn't have permission to use that location. Choose another folder, then try again.")
            case .fileGone:
                return String(localized: "The file or folder is no longer there. Check that it still exists, then try again.")
            case .fileReadWrite:
                return String(localized: "Couldn't read or write a file on your Mac. Check that it still exists and that there's enough space, then try again.")
            }
        }
    }

    /// How an error maps before localization: fixed copy, a Proton
    /// envelope code or HTTP status (copy depends on the number), a queue
    /// message (rendered through `message(forMessage:)`), or text that is
    /// already final (errors carrying their own copy, may quote names).
    private enum Resolution {
        case copy(Copy)
        case code(Int, detail: String)
        case status(Int, detail: String)
        case token(String)
        case text(String)
    }

    /// Actionable one-liner for any error reaching the UI.
    static func message(for error: Error) -> String {
        switch resolve(error) {
        case let .copy(copy): return copy.text
        case let .code(code, detail): return message(forCode: code, message: detail)
        case let .status(status, _): return message(forStatus: status)
        case let .token(token): return message(forMessage: token)
        case let .text(text): return text
        }
    }

    /// The stable, language-neutral, name-free form of `error` that the
    /// queue persists (TransferErrorClassify). `message(forMessage:)` turns
    /// it back into localized copy at display time. Errors that only carry
    /// their own (possibly name-quoting) text persist as the generic copy.
    static func token(for error: Error) -> String {
        switch resolve(error) {
        case let .copy(copy): return copy.token
        // The "api N: …" / "http N: …" shapes `message(forMessage:)` parses.
        case let .code(code, detail): return "api \(code): \(detail)"
        case let .status(status, detail): return "http \(status): \(detail)"
        case let .token(token): return token
        case .text: return Copy.somethingWentWrong.token
        }
    }

    private static func resolve(_ error: Error) -> Resolution {
        if let f = error as? TransferFailure {
            switch f {
            case .needsHumanVerification: return .copy(.humanVerification)
            case .cancelled: return .copy(.uploadStopped)
            case let .transient(msg), let .permanent(msg): return .token(msg)
            }
        }
        if let api = error as? ProtonAPIError {
            return resolve(api: api)
        }
        if let dl = error as? FileDownloadError {
            return .copy(copy(forDownload: dl))
        }
        if let chain = error as? DecryptChainError {
            return .copy(copy(forChain: chain))
        }
        if let source = error as? UploadSourceError {
            return .copy(source == .changedDuringUpload ? .changedDuringUpload : .fileUnreadable)
        }
        if let name = error as? FolderNameError {
            return .text(name.message)
        }
        if error is FileUploadError || isEncryptionError(error) {
            return .copy(.preparingFile)
        }
        if error is FolderCreateError {
            return .copy(.preparingFolder)
        }
        if error is LocalTreeScanError {
            return .copy(.folderUnreadable)
        }
        if isDecryptionError(error) {
            return .copy(.decryptFailed)
        }
        if error is CancellationError {
            return .copy(.cancelled)
        }
        let ns = error as NSError
        if ns.domain == (NSURLErrorDomain as String) {
            return .copy(copy(forURLErrorCode: ns.code))
        }
        if ns.domain == NSCocoaErrorDomain || ns.domain == NSPOSIXErrorDomain {
            return .copy(copy(forFileError: ns))
        }
        // Errors that carry their own user-facing text (e.g. the browser's
        // FolderOperationError) are echoed verbatim — never through the
        // string heuristics, since such text may quote item names.
        if error is LocalizedError, let text = (error as? LocalizedError)?.errorDescription,
           !text.isEmpty
        {
            return .text(text)
        }
        return .copy(.somethingWentWrong)
    }

    /// Failed upload row text (F8.4-U7b): the typed `errorCode` decides
    /// first — Proton 2000 (not allowlisted) gets the short text whatever
    /// the envelope said. Jobs persisted before `errorCode` existed (nil)
    /// fall back to the string path, which still parses "api 2000: …".
    static func message(forJob job: TransferJob) -> String {
        if job.errorCode == UploadBlockDetection.notAllowlistedCode {
            return uploadAllowlisted
        }
        return message(forMessage: job.errorMessage ?? String(localized: "Upload failed"))
    }

    /// Mapping for already-stringified queue messages (TransferJob.errorMessage
    /// persists as String). Understands the name-free tokens written by
    /// `TransferErrorClassify` ("api N: …", "http N: …", "copy <id>",
    /// "rate limited", the fixed local-file tokens), legacy pre-F8.4
    /// strings, and plain status codes (word-boundary match). Anything
    /// already user-facing passes through unchanged, so mapping twice is
    /// harmless.
    static func message(forMessage msg: String) -> String {
        let text = msg.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return somethingWentWrong }
        // 1. Queue tokens: "api 2000: …", "http 503: …", "copy <id>".
        if let token = parseToken(text) {
            return token.isHTTP
                ? message(forStatus: token.code)
                : message(forCode: token.code, message: token.detail)
        }
        if let copy = Copy(token: text) { return copy.text }
        if text.wholeMatch(of: /copy [a-z0-9-]+/) != nil {
            // A copy id from a newer build this one doesn't know.
            return somethingWentWrong
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
            return Copy.incompleteItemData.text
        }
        // 3. Already final: our own "(Error N)" suffix — in any language
        //    ("(Erro N)" in pt-BR, F8.4-U9) — or quoted names (“…”) from
        //    FolderConflictPolicy / FolderNameError copy.
        if text.range(of: #"\(\p{L}+ -?\d+\)\.?$"#, options: .regularExpression) != nil
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

    static var rateLimited: String { Copy.rateLimited.text }
    static var humanVerification: String { Copy.humanVerification.text }
    static var uploadAllowlisted: String { Copy.uploadAllowlisted.text }
    /// Name-free: the row already shows which file it is.
    static var changedDuringUpload: String { Copy.changedDuringUpload.text }
    static var fileMissing: String { Copy.fileMissing.text }
    static var fileUnreadable: String { Copy.fileUnreadable.text }
    static var integrityFailed: String { Copy.integrityFailed.text }
    static var signedOut: String { Copy.signedOut.text }
    static var somethingWentWrong: String { Copy.somethingWentWrong.text }

    // MARK: - typed errors

    private static func resolve(api: ProtonAPIError) -> Resolution {
        switch api {
        case .rateLimited: return .copy(.rateLimited)
        case .humanVerificationRequired: return .copy(.humanVerification)
        case .needs2FA: return .copy(.needsTwoFactor)
        case .unauthorized: return .copy(.signedOut)
        case .invalidServerProof: return .copy(.serverProofInvalid)
        case .invalidModulusSignature: return .copy(.modulusSignatureInvalid)
        case .unsupportedAuthVersion: return .copy(.unsupportedAuthVersion)
        case .secureRandomFailed: return .copy(.secureRandomFailed)
        case .bcryptNotAvailable: return .copy(.bcryptNotAvailable)
        case .invalidBcryptSalt: return .copy(.invalidBcryptSalt)
        case .keyVerificationFailed: return .copy(.keyVerificationFailed)
        case .srpParamsOutOfBounds: return .copy(.srpParamsOutOfBounds)
        case let .api(code, msg):
            return .code(code, detail: msg)
        case let .http(status, code, msg, _):
            // The envelope code is more specific than the status when the
            // body carried one (2028 / 9001 / 2000 ride on 4xx statuses).
            if let code, code != 1000 { return .code(code, detail: msg) }
            return .status(status, detail: msg)
        case .untrustedStorageHost: return .copy(.untrustedStorageHost)
        case let .transport(underlying): return resolve(underlying)
        }
    }

    private static func copy(forDownload error: FileDownloadError) -> Copy {
        switch error {
        case .hashMismatch: return .integrityFailed
        case .badBlockHash, .blockIndexGap: return .unreadableServerData
        case .emptyBlockList: return .emptyBlockList
        case .missingContentKey: return .missingContentKey
        case .missingRevision: return .missingRevision
        case .unsafeDestination: return .unsafeDestination
        case .manifestSignatureMissing: return .manifestSignatureMissing
        case .manifestSignatureInvalid: return .manifestSignatureInvalid
        case .manifestSignatureUnverifiable: return .manifestSignatureUnverifiable
        case .contentKeySignatureInvalid: return .contentKeySignatureInvalid
        case .blockSignatureInvalid: return .blockSignatureInvalid
        case .destinationUnavailable: return .destinationUnavailable
        }
    }

    /// Key-level signature failures (F8.1-S2): the key material was refused,
    /// never used. Actionable: reload; persistent → possible tampering.
    private static func copy(forChain error: DecryptChainError) -> Copy {
        switch error {
        case .missingMaterial: return .incompleteItemData
        case .signatureMissing: return .chainSignatureMissing
        case .signatureInvalid: return .chainSignatureInvalid
        case .weakSignatureHash: return .weakSignatureHash
        case .unknownSigner: return .unknownSigner
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
            return String(localized: "An item with this name already exists here. Rename it and try again. (Error 2500)")
        case 2501:
            // Reused server-side: folder-creation signature rejects AND
            // "Draft file not found" on trash/delete (live-proven F6).
            return String(localized: "Proton couldn't find or accept this item. Reload the folder and try again — if you were deleting it, it may already be gone. (Error 2501)")
        case 2511:
            return String(localized: "This location doesn't accept new items. Upload to a folder in My Files instead. (Error 2511)")
        case 200501:
            return String(localized: "Proton didn't accept the new folder's encryption data. Try again; if it keeps happening, report the problem. (Error 200501)")
        default:
            // Codes interpolate as String: an Int argument would be
            // locale-grouped ("8.002" in pt-BR).
            // Proton's envelope `Error` text is written for end users
            // ("Incorrect login credentials. Please try again.").
            let detail = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !detail.isEmpty else {
                return String(localized: "Proton couldn't complete the request. Try again. (Error \(String(code)))")
            }
            let sentence = detail.hasSuffix(".") || detail.hasSuffix("!") || detail.hasSuffix("?")
                ? detail : detail + "."
            return String(localized: "\(sentence) (Error \(String(code)))")
        }
    }

    /// HTTP statuses without a usable envelope (storage host, bad bodies).
    private static func message(forStatus status: Int) -> String {
        switch status {
        case 401:
            return signedOut
        case 429:
            return String(localized: "Proton is busy right now. Transfers back off and retry on their own — leave the app open. (Error 429)")
        case 500...599:
            return String(localized: "Proton's servers are having trouble. Transfers retry on their own; otherwise try again in a few minutes. (Error \(String(status)))")
        case 404:
            return String(localized: "This item is no longer available. Reload the folder and try again. (Error 404)")
        default:
            return String(localized: "Proton couldn't complete the request. Try again; if it keeps happening, reload the folder. (Error \(String(status)))")
        }
    }

    private static func copy(forURLErrorCode code: Int) -> Copy {
        switch code {
        case NSURLErrorTimedOut, NSURLErrorNetworkConnectionLost,
             NSURLErrorNotConnectedToInternet, NSURLErrorCannotConnectToHost,
             NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed,
             NSURLErrorResourceUnavailable, NSURLErrorInternationalRoamingOff,
             NSURLErrorCallIsActive, NSURLErrorDataNotAllowed:
            return .networkUnreachable
        case NSURLErrorSecureConnectionFailed, NSURLErrorServerCertificateHasBadDate,
             NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateNotYetValid, NSURLErrorClientCertificateRejected,
             NSURLErrorClientCertificateRequired:
            return .serverUnverified
        case NSURLErrorCancelled:
            return .cancelled
        default:
            return .networkError
        }
    }

    /// Local file-system failures (Cocoa / POSIX). Their descriptions quote
    /// file names and paths, so they are never echoed.
    private static func copy(forFileError ns: NSError) -> Copy {
        if ns.domain == NSCocoaErrorDomain {
            switch ns.code {
            case NSFileWriteOutOfSpaceError:
                return .outOfSpace
            case NSFileReadNoPermissionError, NSFileWriteNoPermissionError:
                return .noPermission
            case NSFileNoSuchFileError, NSFileReadNoSuchFileError:
                return .fileGone
            default:
                break
            }
        } else if ns.code == Int(ENOSPC) {
            return .outOfSpace
        }
        return .fileReadWrite
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
