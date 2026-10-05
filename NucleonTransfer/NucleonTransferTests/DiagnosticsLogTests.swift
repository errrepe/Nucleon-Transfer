// Nucleon Transfer — DiagnosticsLog.safeSummary (Swift Testing).
// The summary is logged with `privacy: .public`, so it must carry only
// kinds and numbers: never server messages, hosts or SRP details.
import Foundation
import Testing

@testable import NucleonTransfer

struct DiagnosticsLogTests {
    @Test func httpErrorKeepsStatusAndCodeOnly() {
        let error = ProtonAPIError.http(status: 422, code: 10013, message: "secret-ish server text")
        let summary = DiagnosticsLog.safeSummary(error)
        #expect(summary == "ProtonAPIError.http(status: 422, code: 10013)")
    }

    @Test func apiErrorDropsTheMessage() {
        let summary = DiagnosticsLog.safeSummary(ProtonAPIError.api(code: 10013, message: "Invalid refresh token"))
        #expect(summary == "ProtonAPIError.api(code: 10013)")
    }

    @Test func associatedStringsNeverLeak() {
        #expect(DiagnosticsLog.safeSummary(ProtonAPIError.untrustedStorageHost("evil.example")) == "ProtonAPIError.untrustedStorageHost")
        #expect(DiagnosticsLog.safeSummary(ProtonAPIError.srpParamsOutOfBounds("no key salt for KEYID")) == "ProtonAPIError.srpParamsOutOfBounds")
    }

    @Test func keychainAndTransportAreNumeric() {
        #expect(DiagnosticsLog.safeSummary(KeychainStoreError(status: -34018)) == "KeychainStoreError(status: -34018)")
        let transport = ProtonAPIError.transport(URLError(.notConnectedToInternet))
        #expect(DiagnosticsLog.safeSummary(transport) == "ProtonAPIError.transport(URLError(code: -1009))")
        #expect(DiagnosticsLog.safeSummary(CancellationError()) == "CancellationError")
    }
}
