// Nucleon Transfer — 2FA code field rules + login links (F8.4-U5).
// Offline only: input filtering for authenticator vs recovery codes,
// completeness / auto-submit, the mode-specific wrong-code copy, and the
// account web links the login screen opens.
import Foundation
import Testing

@testable import NucleonTransfer

struct TwoFactorCodeInputTests {
    @Test func authenticatorKeepsSixAsciiDigits() {
        #expect(TwoFactorCodeInput.filter("12 34-56", mode: .authenticator) == "123456")
        #expect(TwoFactorCodeInput.filter("1234567", mode: .authenticator) == "123456")
        #expect(TwoFactorCodeInput.filter("abc12", mode: .authenticator) == "12")
        // Non-ASCII digits (Arabic-Indic, full-width) are not TOTP digits.
        #expect(TwoFactorCodeInput.filter("١٢٣４５６", mode: .authenticator) == "")
    }

    @Test func recoveryCodeKeepsLettersAndDropsWhitespace() {
        #expect(TwoFactorCodeInput.filter(" a1b2 c3d4\n", mode: .recoveryCode) == "a1b2c3d4")
        #expect(TwoFactorCodeInput.filter("AbCd-1234", mode: .recoveryCode) == "AbCd-1234")
        #expect(TwoFactorCodeInput.filter("x\t\u{0}y", mode: .recoveryCode) == "xy")
        let long = String(repeating: "a", count: 200)
        #expect(TwoFactorCodeInput.filter(long, mode: .recoveryCode).count == TwoFactorCodeInput.recoveryMaxLength)
    }

    @Test func completenessAndAutoSubmit() {
        #expect(TwoFactorCodeInput.isComplete("123456", mode: .authenticator))
        #expect(!TwoFactorCodeInput.isComplete("12345", mode: .authenticator))
        #expect(!TwoFactorCodeInput.isComplete("12345a", mode: .authenticator))
        #expect(TwoFactorCodeInput.shouldAutoSubmit("123456", mode: .authenticator))
        // Recovery codes have no fixed length: Return/Verify only.
        #expect(TwoFactorCodeInput.isComplete("a1b2c3d4", mode: .recoveryCode))
        #expect(!TwoFactorCodeInput.isComplete("   ", mode: .recoveryCode))
        #expect(!TwoFactorCodeInput.shouldAutoSubmit("a1b2c3d4", mode: .recoveryCode))
        #expect(!TwoFactorCodeInput.shouldAutoSubmit("123456", mode: .recoveryCode))
    }

    @Test func wrongCodeCopyFollowsTheMode() {
        let wrong = ProtonAPIError.api(code: 8002, message: "Incorrect code")
        #expect(TwoFactorFailure.message(for: wrong).contains("authenticator app"))
        let recovery = TwoFactorFailure.message(for: wrong, mode: .recoveryCode)
        #expect(recovery.contains("recovery code"))
        #expect(!recovery.contains("authenticator"))
        // Non-code failures read the same in both modes.
        let offline = URLError(.notConnectedToInternet)
        #expect(TwoFactorFailure.message(for: offline, mode: .recoveryCode)
            == TwoFactorFailure.message(for: offline))
    }

    @Test func accountLinksPointAtProtonAccountPages() throws {
        let reset = try #require(AccountLinks.resetPassword)
        let signup = try #require(AccountLinks.createAccount)
        for url in [reset, signup] {
            #expect(url.scheme == "https")
            #expect(url.host() == "account.proton.me")
        }
        #expect(reset.path() == "/reset-password")
        #expect(signup.path() == "/signup")
    }
}
