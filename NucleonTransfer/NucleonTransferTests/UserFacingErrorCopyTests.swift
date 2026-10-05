// Nucleon Transfer — user-facing error copy (F8.4-U2).
// Table-driven over every typed error the app surfaces: plain language,
// no protocol jargon or enum dumps, codes only as a trailing "(Error N)",
// and file names never steer the string heuristics. Offline only.
import Foundation
import Testing

@testable import NucleonTransfer

struct UserFacingErrorCopyTests {
    /// Every case UserFacingError classifies by type.
    static var typedErrors: [any Error] { [
        // ProtonAPIError
        ProtonAPIError.api(code: 2501, message: "Draft file not found"),
        ProtonAPIError.api(code: 2000, message: "You are using an outdated version of the app."),
        ProtonAPIError.api(code: 2028, message: "Too many recent logins"),
        ProtonAPIError.api(code: 2500, message: "A file or folder with that name already exists"),
        ProtonAPIError.api(code: 2511, message: "photo"),
        ProtonAPIError.api(code: 200501, message: "bad key"),
        ProtonAPIError.api(code: 8002, message: "Incorrect login credentials. Please try again."),
        ProtonAPIError.api(code: 503, message: "down"),
        ProtonAPIError.unauthorized,
        ProtonAPIError.needs2FA,
        ProtonAPIError.humanVerificationRequired,
        ProtonAPIError.invalidServerProof,
        ProtonAPIError.invalidModulusSignature,
        ProtonAPIError.srpParamsOutOfBounds("g out of range"),
        ProtonAPIError.unsupportedAuthVersion(2),
        ProtonAPIError.secureRandomFailed,
        ProtonAPIError.bcryptNotAvailable,
        ProtonAPIError.invalidBcryptSalt,
        ProtonAPIError.keyVerificationFailed,
        ProtonAPIError.rateLimited,
        ProtonAPIError.http(status: 503, code: nil, message: "storage HTTP 503"),
        ProtonAPIError.http(status: 422, code: 2000, message: "outdated"),
        ProtonAPIError.http(status: 404, code: nil, message: "storage HTTP 404"),
        ProtonAPIError.http(status: 400, code: nil, message: "storage HTTP 400"),
        ProtonAPIError.untrustedStorageHost("evil.example"),
        ProtonAPIError.transport(URLError(.notConnectedToInternet)),
        ProtonAPIError.transport(URLError(.serverCertificateUntrusted)),
        // TransferFailure
        TransferFailure.transient("api 502: bad gateway"),
        TransferFailure.permanent("http 500: storage HTTP 500"),
        TransferFailure.needsHumanVerification,
        TransferFailure.cancelled,
        // FileDownloadError
        FileDownloadError.hashMismatch(index: 3),
        FileDownloadError.badBlockHash("abcdef0123456789"),
        FileDownloadError.blockIndexGap,
        FileDownloadError.emptyBlockList,
        FileDownloadError.missingContentKey,
        FileDownloadError.missingRevision,
        FileDownloadError.unsafeDestination,
        FileDownloadError.manifestSignatureMissing,
        FileDownloadError.manifestSignatureInvalid,
        FileDownloadError.manifestSignatureUnverifiable,
        FileDownloadError.contentKeySignatureInvalid,
        FileDownloadError.blockSignatureInvalid(index: 1),
        FileDownloadError.destinationUnavailable,
        // DecryptChainError
        DecryptChainError.missingMaterial("share passphrase/key"),
        DecryptChainError.signatureMissing(what: "node passphrase"),
        DecryptChainError.signatureInvalid(what: "node key"),
        DecryptChainError.weakSignatureHash(what: "node key", algo: 2),
        DecryptChainError.unknownSigner(what: "node key"),
        // Local sources / upload preparation
        UploadSourceError.changedDuringUpload,
        UploadSourceError.cannotOpen(errno: 2),
        UploadSourceError.readFailed(errno: 5),
        UploadSourceError.truncated,
        FileUploadError.noNodeSigningKey,
        FileUploadError.uploadLinkMismatch,
        FolderCreateError.badHashKeyLength,
        LocalTreeScanError.unreadable("/Users/x/photo500"),
        // System
        URLError(.timedOut),
        URLError(.secureConnectionFailed),
        URLError(.badServerResponse),
        CancellationError(),
        CocoaError(.fileWriteOutOfSpace),
        CocoaError(.fileReadNoPermission),
        CocoaError(.fileReadCorruptFile),
        NSError(domain: NSPOSIXErrorDomain, code: Int(ENOENT)),
    ] }

    static let jargon = [
        "Proton API", "appversion", "rclone", "downgrade", "bcrypt", "SRP",
        "allowlist", "HTTP ", "Optional(", "NucleonTransfer.", "errno",
        "error 0.", "TOTP",
    ]

    @Test(arguments: typedErrors.indices)
    func messageIsPlainLanguage(index: Int) {
        let error = Self.typedErrors[index]
        let msg = UserFacingError.message(for: error)
        #expect(!msg.isEmpty)
        for word in Self.jargon {
            #expect(!msg.contains(word), "\(error) → \(msg)")
        }
        // A raw enum dump would echo the case name.
        let caseName = String(describing: error).split(separator: "(").first.map(String.init) ?? ""
        if caseName.count > 6 {
            #expect(!msg.contains(caseName), "\(error) → \(msg)")
        }
        // Codes only as a trailing "(Error N)".
        if let code = msg.firstMatch(of: /\d{3,}/) {
            #expect(msg.hasSuffix("(Error \(code.output)).") || msg.hasSuffix("(Error \(code.output))"),
                    "\(error) → \(msg)")
        }
        // Mapping the stored string again (download records, queue rows)
        // changes nothing.
        #expect(UserFacingError.message(forMessage: msg) == msg, "\(error) → \(msg)")
        // LocalizedError for ProtonAPIError matches the UI copy.
        if let api = error as? ProtonAPIError {
            #expect(api.localizedDescription == msg)
        }
    }

    @Test func codesTrailInErrorParentheses() {
        #expect(UserFacingError.message(for: ProtonAPIError.api(code: 2501, message: "x")).hasSuffix("(Error 2501)"))
        #expect(UserFacingError.message(for: ProtonAPIError.rateLimited).hasSuffix("(Error 2028)"))
        #expect(UserFacingError.message(for: ProtonAPIError.http(status: 502, code: nil, message: "m")).hasSuffix("(Error 502)"))
        #expect(UserFacingError.message(for: ProtonAPIError.api(code: 8002, message: "Incorrect login credentials. Please try again."))
            == "Incorrect login credentials. Please try again. (Error 8002)")
    }

    @Test func uploadAllowlistRowText() {
        let expected = "Upload not available yet (Error 2000)."
        #expect(UserFacingError.message(for: ProtonAPIError.api(code: 2000, message: "outdated")) == expected)
        #expect(UserFacingError.message(for: ProtonAPIError.http(status: 422, code: 2000, message: "outdated")) == expected)
        #expect(UserFacingError.message(forMessage: "api 2000: You are using an outdated version of the app.") == expected)
    }

    @Test func securityFailuresKeepTheirMeaning() {
        let modulus = UserFacingError.message(for: ProtonAPIError.invalidModulusSignature)
        #expect(modulus.contains("Couldn't verify the connection"))
        #expect(modulus.contains("don't sign in on this network"))
        let proof = UserFacingError.message(for: ProtonAPIError.invalidServerProof)
        #expect(proof.contains("Couldn't verify Proton's server"))
        #expect(proof.contains("don't sign in on this network"))
        #expect(UserFacingError.message(for: URLError(.serverCertificateUntrusted))
            == "Couldn't verify Proton's server. Check your network (VPN or proxy) and try again.")
    }

    // MARK: - file names never steer the heuristics

    @Test(arguments: ["IMG_5001.jpg", "photo.jpg", "photo500.jpg", "report 503.pdf", "unauthorized.txt"])
    func fileNamesDoNotTriggerGuidance(name: String) {
        // Producers keep names out of queue messages…
        #expect(!UserFacingError.fileMissing.contains(name))
        #expect(!UploadSourceError.changedMessage.contains(name))
        // …and legacy (pre-F8.4) persisted strings that embedded a name map
        // by prefix, without looking at the name.
        #expect(UserFacingError.message(forMessage: "local file missing — re-add \(name)") == UserFacingError.fileMissing)
        #expect(UserFacingError.message(forMessage: "cannot read \(name): Permission denied") == UserFacingError.fileUnreadable)
        #expect(UserFacingError.message(forMessage: "\(name) changed while it was uploading. Try again.")
            == UserFacingError.changedDuringUpload)
        // Quoted names in already-final copy pass through untouched.
        let conflict = "A file named “\(name)” already exists here, so the folder can’t be created."
        #expect(UserFacingError.message(forMessage: conflict) == conflict)
        // A Cocoa error quoting the name never reaches the string path.
        let cocoa = CocoaError(.fileReadNoSuchFile, userInfo: [NSFilePathErrorKey: "/tmp/\(name)"])
        let mapped = UserFacingError.message(for: cocoa)
        #expect(!mapped.contains(name))
        #expect(!mapped.contains("server"))
        #expect(!mapped.contains("My Files"))
    }

    @Test func statusCodesMatchOnWordBoundaries() {
        #expect(UserFacingError.message(forMessage: "IMG_5001 upload") == "IMG_5001 upload")
        #expect(UserFacingError.message(forMessage: "photo") == "photo") // no Photos-share guess
        #expect(UserFacingError.message(forMessage: "gateway answered 502").hasSuffix("(Error 502)"))
        #expect(UserFacingError.message(forMessage: "x15030y") == "x15030y")
    }

    @Test func classifyStoresNameFreeUserCopy() {
        // Queue tokens stay parseable ("api N:"), everything else is copy.
        #expect(TransferErrorClassify.classify(ProtonAPIError.api(code: 2000, message: "m")) == .permanent("api 2000: m"))
        let cocoa = CocoaError(.fileReadNoSuchFile, userInfo: [NSFilePathErrorKey: "/tmp/IMG_5001.jpg"])
        guard case let .permanent(stored) = TransferErrorClassify.classify(cocoa) else {
            Issue.record("expected permanent")
            return
        }
        #expect(!stored.contains("IMG_5001"))
    }
}
