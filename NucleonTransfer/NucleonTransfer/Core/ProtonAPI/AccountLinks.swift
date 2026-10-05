// Nucleon Transfer — Proton account web pages linked from the login
// screen (F8.4-U5). Both are routes of the account web app
// (WebClients packages/shared/lib/constants.ts SSO_PATHS: RESET_PASSWORD
// '/reset-password'; account app public routes: signup '/signup'), and
// answered HTTP 200 on 2026-10-04. Account recovery and sign-up need
// Proton's own flows (human verification, payment) — the app only links.
import Foundation

enum AccountLinks {
    static let resetPassword = URL(string: "https://account.proton.me/reset-password")
    static let createAccount = URL(string: "https://account.proton.me/signup")
}
