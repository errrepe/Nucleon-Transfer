// Nucleon Transfer — diagnostics log (F8.5 live-check follow-up).
// Unified-logging channel for "Keep me signed in": where a save or a
// restore failed, so a live failure can be read back with
//   log show --predicate 'subsystem == "dev.nucleon.NucleonTransfer"' --info --last 10m
// Only `safeSummary` text is logged: error kind, HTTP status, Proton code,
// OSStatus. Never tokens, passwords, salts, usernames, server messages or
// URLs (block URLs carry tokens in-path) — those stay out by construction.
import Foundation
import os

enum DiagnosticsLog {
    static let session = Logger(subsystem: subsystem, category: "session")

    private static var subsystem: String {
        Bundle.main.bundleIdentifier ?? "dev.nucleon.NucleonTransfer"
    }

    /// A secret-free one-line description of `error`, safe to log with
    /// `privacy: .public`.
    static func safeSummary(_ error: Error) -> String {
        if let api = error as? ProtonAPIError {
            switch api {
            case let .api(code, _): return "ProtonAPIError.api(code: \(code))"
            case let .http(status, code, _, _):
                return "ProtonAPIError.http(status: \(status), code: \(code.map(String.init) ?? "nil"))"
            case let .transport(inner): return "ProtonAPIError.transport(\(safeSummary(inner)))"
            case let .unsupportedAuthVersion(version): return "ProtonAPIError.unsupportedAuthVersion(\(version))"
            case .untrustedStorageHost: return "ProtonAPIError.untrustedStorageHost"
            case .srpParamsOutOfBounds: return "ProtonAPIError.srpParamsOutOfBounds"
            case .unauthorized: return "ProtonAPIError.unauthorized"
            case .needs2FA: return "ProtonAPIError.needs2FA"
            case .humanVerificationRequired: return "ProtonAPIError.humanVerificationRequired"
            case .invalidServerProof: return "ProtonAPIError.invalidServerProof"
            case .invalidModulusSignature: return "ProtonAPIError.invalidModulusSignature"
            case .secureRandomFailed: return "ProtonAPIError.secureRandomFailed"
            case .bcryptNotAvailable: return "ProtonAPIError.bcryptNotAvailable"
            case .invalidBcryptSalt: return "ProtonAPIError.invalidBcryptSalt"
            case .keyVerificationFailed: return "ProtonAPIError.keyVerificationFailed"
            case .rateLimited: return "ProtonAPIError.rateLimited"
            }
        }
        if let keychain = error as? KeychainStoreError {
            return "KeychainStoreError(status: \(keychain.status))"
        }
        if error is CancellationError { return "CancellationError" }
        if let url = error as? URLError { return "URLError(code: \(url.code.rawValue))" }
        let ns = error as NSError
        return "\(type(of: error)) (\(ns.domain) \(ns.code))"
    }
}
