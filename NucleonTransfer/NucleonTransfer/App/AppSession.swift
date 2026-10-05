// Nucleon Transfer — session root: single DI container + auth lifecycle (F7).
// Owns the ONLY SessionManager / KeyringCache / DriveClient / TransferQueue /
// TransferActivityStore; views read them via .environment (injected at the
// WindowGroup). Secrets stay inside the owning actors, memory only; the
// password is retained as Data solely between signIn and the post-2FA key
// unlock, and that buffer is zeroed on every path (success, error, cancel,
// sign-out). Best-effort: the String the login field handed over, and any
// copy the runtime made, cannot be wiped (F8.1-S7).
// F8.5 "Keep me signed in" (opt-in): after a full login the refresh token,
// UID and salted key password go to SessionVault (Keychain, this device
// only); every token rotation is written through; launch restores it
// (`.restoring`) through the same `finishUnlock` tail as a password
// login. Sign-out deletes the item before anything else.
// F8.5-V3 "Require Touch ID": the stored blob is sealed under a Touch ID
// protected KEK (SessionVault); the restore's first step is the Touch ID
// prompt — cancel keeps the items and offers "Use Touch ID", changed
// fingerprints delete them. Settings re-seals/unseals the live item and
// "Forget This Mac" drops both items + the remembered username.
// F8.5 review: launch restore runs once per app launch and only while
// "Keep me signed in" is on (else the item is deleted); both toggles go
// through `setKeepSignedIn`; token rotations arrive on
// `SessionManager.tokenChanges`, consumed in order by one Task; the last
// username is persisted only with "Keep me signed in".
import Foundation
import os

@MainActor
@Observable
final class AppSession {
    enum Phase: Equatable {
        case signedOut
        case signingIn      // SRP handshake in flight
        case needsTwoFactor // TOTP required; password retained for post-2FA unlock
        case unlocking      // session OK; decrypting key hierarchy (salts → user → address)
        case restoring      // F8.5: remembered session — refresh + key unlock, no password
        case signedIn
    }

    /// Public account summary for the shell header (email, display name, quota).
    struct Account: Equatable, Sendable {
        var email: String
        var displayName: String
        var usedBytes: Int64
        var maxBytes: Int64?
    }

    private(set) var phase: Phase = .signedOut
    private(set) var account: Account?
    /// Error or sign-out reason shown on the login screen.
    var loginError: String?
    /// F8.2-R7: the TOTP code is being checked — TwoFactorView shows
    /// "Verifying…" inline; the phase only moves to `.unlocking` once
    /// Proton accepted the code.
    private(set) var isVerifyingTwoFactor = false
    /// F8.2-R7: inline error on the 2FA prompt (wrong code, network) —
    /// the user stays on the prompt with the session and password intact.
    private(set) var twoFactorError: String?
    /// Proton user ID of the signed-in account — scopes the upload queue
    /// (F8.2-R7 / B12). nil while signed out.
    private(set) var accountID: String?
    /// F8.5: the last restore failed on the network and the remembered
    /// session was KEPT — the login screen offers Retry (RestoreFailure).
    private(set) var canRetryRestore = false
    /// F8.5-V3: Touch ID was cancelled / unavailable at restore and the
    /// sealed session was KEPT — the login screen offers "Use Touch ID".
    private(set) var canRetryTouchID = false
    /// App menu "Sign Out…" while the shell is up: the sidebar footer
    /// picks this up and runs its confirmation flow (active-transfers
    /// warning), even when the request came from the Settings window.
    var signOutRequested = false

    let activity = TransferActivityStore()
    let queue: TransferQueue
    let sessions: SessionManager
    let keyrings: KeyringCache
    /// The ONLY DriveClient in the app — features share this instance.
    let drive: DriveClient
    /// "Keep me signed in" storage (F8.5) — Keychain in the app, in-memory
    /// for previews/demo.
    let vault: SessionVault
    /// Settings source (keep-signed-in preference, last username).
    private let defaults: UserDefaults
    /// True while the Keychain item belongs to the live session: token
    /// rotations are written through to it. Set before a restore's own
    /// refresh and before saving; cleared synchronously at sign-out,
    /// before any await, so a late rotation can't rewrite a deleted item
    /// (`updateTokens` never creates one either).
    private var remembersSession = false
    /// Consumes `sessions.tokenChanges` for the app's lifetime, one event
    /// at a time and in order (see `tokensChanged`).
    private var tokenConsumer: Task<Void, Never>?
    /// The launch restore already ran (or is running) — reopening the
    /// window must not start another one (F8.5 review).
    private var didAttemptLaunchRestore = false

    /// Unlocked address keys (share-passphrase chain root). Memory only.
    private(set) var addressKeys: [KeyringCache.UnlockedKey] = []
    /// Single resolver for share/node key material (S1.2) — shared by the
    /// upload/download adapters; created once `addressKeys` unlock, reset +
    /// dropped on sign-out.
    private(set) var resolver: NodeKeyResolver?
    /// Listing service (S1.3) — created alongside the resolver, dropped on
    /// sign-out. Stateless glue: all key/link state lives in `resolver`.
    /// Protocol-typed so DEBUG builds can swap in the offline demo fixture.
    private(set) var listing: (any DriveListingProviding)?
    /// Browser download orchestrator (S2.3) — created alongside the
    /// resolver, cancelled + dropped on sign-out. Holds no state of its own
    /// beyond in-flight dedup and per-download Task handles (F8.2-R5); all
    /// progress lands in `activity`.
    private(set) var downloads: DownloadCoordinator?
    /// Folder write ops (create/trash, S2.3) — created alongside the
    /// resolver, dropped on sign-out. nil ⇒ the write UI stays disabled.
    private(set) var folderOps: FolderOperations?
    /// Upload orchestrator (S3.1) — created alongside the resolver,
    /// stopped + dropped on sign-out. Owns the queue's live uploader and
    /// snapshot listener so completed uploads mark their remote parents
    /// stale; nil ⇒ the upload UI stays disabled.
    private(set) var uploads: UploadCoordinator?
    /// Classified drive roots for the shell (My Files / Photos / Computers);
    /// nil until `loadRoots` succeeds.
    private(set) var roots: DriveRoots?
    /// Last `loadRoots` failure, user-facing — drives the shell error
    /// state (S2.1).
    private(set) var rootsError: String?
    /// Retained only between signIn and the post-2FA unlock; zeroed on exit.
    private var pendingPassword: Data?
    /// Username being signed in — account fallback when /users has no
    /// email, and the login field's prefill after a failed 2FA lands back
    /// on the login screen (S4.3 audit).
    private(set) var loginUsername: String?

    init(
        queueStoreURL: URL? = TransferQueue.defaultStoreURL(),
        vault: SessionVault? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.vault = vault ?? SessionVault(store: LiveKeychainStore())
        self.defaults = defaults
        let sessions = SessionManager()
        self.sessions = sessions
        keyrings = KeyringCache(sessions: sessions)
        drive = DriveClient(sessions: sessions)
        // B12: nothing in the shared snapshot is visible or runnable until
        // an account signs in (finishSignIn scopes the queue to it).
        queue = TransferQueue(storeURL: queueStoreURL, accountScope: .signedOut)
        tokenConsumer = Task { [weak self, changes = sessions.tokenChanges] in
            for await tokens in changes {
                await self?.tokensChanged(tokens)
            }
        }
    }

    // MARK: - sign-in

    /// SRP login, then the key-hierarchy unlock while the password grant is
    /// fresh (salts → user keys → address keys), then account info.
    /// Throws-needs2FA parks the phase and keeps `pendingPassword` alive for
    /// `submitTwoFactor` — every other exit zeroes it.
    func signIn(username: String, password: String) async {
        guard phase != .signingIn, phase != .unlocking else { return }
        phase = .signingIn
        loginError = nil
        twoFactorError = nil
        canRetryRestore = false
        canRetryTouchID = false
        loginUsername = username
        clearPendingPassword() // re-entry: never overwrite live bytes unzeroed
        pendingPassword = Data(password.utf8)
        do {
            guard let pwd = pendingPassword else { throw ProtonAPIError.unauthorized }
            try await sessions.login(username: username, password: pwd)
        } catch let e as ProtonAPIError where e == .needs2FA {
            // Keep pendingPassword: the unlock still runs after submitTwoFactor.
            phase = .needsTwoFactor
            return
        } catch {
            // The SRP exchange failed: no session was stored (login only
            // installs one after the server proof checks out).
            loginError = Self.signInFailureMessage(error)
            phase = .signedOut
            clearPendingPassword()
            return
        }
        phase = .unlocking
        await completeSignIn()
    }

    /// Completes a 2FA-gated login (TOTP or recovery code — both go in the
    /// same `TwoFactorCode` field, see TwoFactorCodeInput), then the same
    /// unlock path.
    /// F8.2-R7: a wrong code (or a network blip) keeps the prompt up with
    /// an inline error, the half-open session and the retained password —
    /// re-entering the password would cost another login against Proton's
    /// 2028 rate limit. Only unrecoverable failures (session gone, rate
    /// limited, human verification) sign out, with the full cleanup.
    func submitTwoFactor(code: String, mode: TwoFactorCodeInput.Mode = .authenticator) async {
        guard phase == .needsTwoFactor, !isVerifyingTwoFactor else { return }
        isVerifyingTwoFactor = true
        twoFactorError = nil
        do {
            try await sessions.submit2FA(code: TwoFactorCodeInput.filter(code, mode: mode))
        } catch {
            isVerifyingTwoFactor = false
            // Signed out / cancelled while the request was in flight.
            guard phase == .needsTwoFactor else { return }
            if TwoFactorFailure.isRecoverable(error) {
                twoFactorError = TwoFactorFailure.message(for: error, mode: mode)
            } else {
                await abortSignIn(reason: UserFacingError.message(for: error))
            }
            return
        }
        isVerifyingTwoFactor = false
        guard phase == .needsTwoFactor else { return }
        phase = .unlocking
        await completeSignIn()
    }

    /// The prompt switched between authenticator and recovery code: the
    /// previous mode's error no longer applies (F8.4-U5).
    func clearTwoFactorError() {
        guard !isVerifyingTwoFactor else { return }
        twoFactorError = nil
    }

    /// Backs out of the 2FA prompt — a plain sign-out with no error message.
    func cancelTwoFactor() async {
        guard !isVerifyingTwoFactor else { return }
        await signOut()
    }

    /// The authenticated half of sign-in: key unlock, account header,
    /// roots. F8.2-R7: a failure here happens with live tokens in
    /// SessionManager and (possibly) user-key seeds in KeyringCache, so it
    /// runs the full `signOut` cleanup — server-side revoke, keyring lock,
    /// resolver reset, password wipe — and lands on the login screen with
    /// the error.
    private func completeSignIn() async {
        do {
            try await finishSignIn()
        } catch {
            await abortSignIn(reason: Self.signInFailureMessage(error))
            return
        }
        clearPendingPassword()
        // Prefill only for users who opted in (F8.5 review).
        if let loginUsername { AppSettings.recordSignIn(username: loginUsername, in: defaults) }
        await refreshAccount()
        phase = .signedIn
        await loadRoots()
    }

    // MARK: - keep me signed in (F8.5)

    /// Launch path: the first call per app launch runs the restore; later
    /// ones (the window reopened, a second scene) do nothing. The flag is
    /// set before any suspension, so two racing callers can't both pass.
    func restoreOnLaunch() async {
        guard !didAttemptLaunchRestore else { return }
        didAttemptLaunchRestore = true
        await restoreRememberedSession()
    }

    /// `restoreOnLaunch` and the login screen's Retry: resumes
    /// the remembered session, if any — refresh from the stored token, then
    /// the shared `finishUnlock` with the stored salted key password.
    /// Failure policy (RestoreFailure): a plain network failure KEEPS the
    /// Keychain item and offers Retry; anything else (401 / refresh token
    /// rejected / key unlock failed) deletes it and lands on the password
    /// login, username prefilled, with a short "sign in again" note.
    /// V3: a sealed item first needs the Touch ID KEK (`vault.unlock`) —
    /// cancel / unavailable keeps it and offers "Use Touch ID"; changed
    /// fingerprints delete it. No network call happens before that.
    /// With "Keep me signed in" off nothing is resumed: any item is
    /// deleted instead (F8.5 review).
    func restoreRememberedSession() async {
        guard phase == .signedOut else { return }
        guard await SavedSignIn.mayRestore(vault: vault, defaults: defaults),
              await vault.hasRememberedSession()
        else {
            canRetryRestore = false
            canRetryTouchID = false
            return
        }
        guard phase == .signedOut else { return }
        phase = .restoring
        loginError = nil
        twoFactorError = nil
        canRetryRestore = false
        canRetryTouchID = false
        var remembered: RememberedSession
        switch await vault.unlock(reason: Self.touchIDUnlockReason) {
        case let .session(session):
            remembered = session
        case .absent:
            if phase == .restoring { phase = .signedOut }
            return
        case let .failed(failure):
            guard phase == .restoring else { return }
            DiagnosticsLog.session.error("restore: vault unlock failed (\(String(describing: failure), privacy: .public))")
            let decision = RestoreFailure.decision(for: failure)
            canRetryTouchID = RestoreFailure.keepsRememberedSession(decision)
            loginError = RestoreFailure.message(for: decision)
            phase = .signedOut
            return
        }
        // Drop our copy of the salted key password once done (best-effort:
        // by then KeyringCache's unlock has released its references).
        defer { remembered.wipe() }
        guard phase == .restoring else { return }
        loginUsername = remembered.username
        // The restore's own refresh rotates the refresh token — it must
        // land in the Keychain, or the next launch would replay a spent one.
        remembersSession = true
        var step = "token refresh"
        do {
            try await sessions.restore(uid: remembered.uid, refreshToken: remembered.refreshToken)
            guard phase == .restoring else { return }
            step = "key unlock"
            try await finishUnlock(saltedPass: remembered.saltedKeyPass)
        } catch {
            DiagnosticsLog.session.error("restore: \(step, privacy: .public) failed: \(DiagnosticsLog.safeSummary(error), privacy: .public)")
            guard phase == .restoring else { return }
            await failRestore(error)
            return
        }
        DiagnosticsLog.session.info("restore: succeeded")
        guard phase == .restoring else { return }
        await refreshAccount()
        phase = .signedIn
        await loadRoots()
    }

    /// "Keep me signed in" switched — the single path for the login
    /// checkbox and Settings › Account (F8.5 review): writes the
    /// preference now (the @AppStorage toggles follow it) and, when off,
    /// deletes the remembered session. Never touches the live session.
    func setKeepSignedIn(_ keep: Bool) async {
        if !keep {
            remembersSession = false
            canRetryRestore = false
            canRetryTouchID = false
        }
        await SavedSignIn.setKeepSignedIn(keep, vault: vault, defaults: defaults)
    }

    /// Settings › "Forget This Mac": deletes the remembered session (both
    /// Keychain items) and the remembered username. The live session, if
    /// any, keeps running — it just won't be resumed after quitting.
    func forgetThisMac() async {
        remembersSession = false
        canRetryRestore = false
        canRetryTouchID = false
        await SavedSignIn.forgetThisMac(vault: vault, defaults: defaults)
    }

    /// Settings › "Require Touch ID" switched: re-seal (on) or unseal (off)
    /// the stored session, if any — may show Touch ID when turning off
    /// without the key in memory. false = not applied (toggle reverts).
    func setRequireTouchID(_ required: Bool) async -> Bool {
        await vault.setSealed(required, reason: Self.touchIDDisableReason)
    }

    /// Touch ID prompt text ("Nucleon Transfer is trying to …").
    static var touchIDUnlockReason: String {
        String(localized: "unlock your saved sign-in",
               comment: "Touch ID prompt: “Nucleon Transfer is trying to unlock your saved sign-in.”")
    }

    static var touchIDDisableReason: String {
        String(localized: "turn off Touch ID for your saved sign-in",
               comment: "Touch ID prompt when switching Require Touch ID off")
    }

    /// Restore failed: full cleanup either way. Network failure → keep the
    /// item, drop the half-session locally WITHOUT revoking it server-side
    /// (its refresh token is what Retry needs). Auth/unlock failure →
    /// `signOut` (deletes the item first, revokes if there is a session).
    private func failRestore(_ error: Error) async {
        let username = loginUsername
        let decision = RestoreFailure.decision(for: error)
        await tearDown(reason: RestoreFailure.message(for: decision),
                       keepRemembered: RestoreFailure.keepsRememberedSession(decision))
        canRetryRestore = decision == .keepAndRetry
        loginUsername = username
    }

    /// After a full password login (incl. 2FA): stores the remembered
    /// session when "Keep me signed in" is on, otherwise makes sure none
    /// is left. `saltedPass` is the caller's buffer (wiped by its owner).
    /// A Keychain failure never fails the sign-in — the session just isn't
    /// remembered.
    /// V3: "Require Touch ID" seals it under a fresh Touch ID KEK; when
    /// Touch ID is required but not available right now (lid closed, no
    /// enrolled finger) nothing is stored — never a silent plain copy.
    private func rememberSessionIfEnabled(saltedPass: Data) async {
        let sealed = AppSettings.requiresTouchID(defaults)
        guard AppSettings.keepsSignedIn(defaults), let username = loginUsername,
              !sealed || BiometryAvailability.isAvailable(),
              let tokens = await sessions.currentTokens()
        else {
            DiagnosticsLog.session.info("save: skipped (keepSignedIn: \(AppSettings.keepsSignedIn(self.defaults), privacy: .public), sealed: \(sealed, privacy: .public))")
            remembersSession = false
            await vault.delete()
            return
        }
        remembersSession = true
        do {
            // A fresh login always starts a fresh KEK (any cached one
            // belonged to the previous item).
            await vault.lock()
            try await vault.save(RememberedSession(
                uid: tokens.uid, refreshToken: tokens.refreshToken,
                saltedKeyPass: saltedPass, username: username
            ), sealed: sealed)
            // A rotation that landed while saving went to the old item (or
            // nowhere): re-sync to the current token.
            if let latest = await sessions.currentTokens(), latest != tokens {
                try await vault.updateTokens(uid: latest.uid, refreshToken: latest.refreshToken)
            }
            DiagnosticsLog.session.info("save: remembered session stored (sealed: \(sealed, privacy: .public))")
        } catch {
            DiagnosticsLog.session.error("save: failed: \(DiagnosticsLog.safeSummary(error), privacy: .public)")
            remembersSession = false
            await vault.delete()
        }
    }

    /// Token rotation → Keychain, only while the item belongs to the live
    /// session. nil (session ended) is deliberately ignored: sign-out
    /// deletes the item itself, first, and a network-failed restore keeps
    /// it on purpose. Events arrive after the fact (the refresh doesn't
    /// wait for us), so the event only says "something changed": what is
    /// written is the CURRENT token — a stale event processed after
    /// `rememberSessionIfEnabled` saved a newer token can never roll the
    /// item back to a spent one. A failed write leaves the old (spent)
    /// token behind; the next restore then fails as an auth error and
    /// deletes the item.
    private func tokensChanged(_ tokens: SessionTokens?) async {
        guard tokens != nil, remembersSession else { return }
        guard let latest = await sessions.currentTokens(), remembersSession else { return }
        do {
            try await vault.updateTokens(uid: latest.uid, refreshToken: latest.refreshToken)
            DiagnosticsLog.session.info("rotation: stored refreshed tokens")
        } catch {
            DiagnosticsLog.session.error("rotation: store failed: \(DiagnosticsLog.safeSummary(error), privacy: .public)")
        }
    }

    /// Full `signOut` cleanup for a sign-in that got past SRP and then
    /// failed; keeps the typed username so the login field is prefilled.
    private func abortSignIn(reason: String) async {
        let username = loginUsername
        await signOut(reason: reason)
        loginUsername = username
    }

    private static func signInFailureMessage(_ error: Error) -> String {
        UserFacingError.message(for: error)
    }

    /// Sign-out order (S0.3; F8.5): delete the remembered session FIRST —
    /// before any network call and before keys drop — then cancel in-flight
    /// downloads and pause + detach the upload queue BEFORE dropping auth,
    /// revoke the session server-side (best-effort), wipe key seeds, then
    /// reset UI-visible state. `reason` lands on the login screen. Every
    /// sign-out forgets the remembered session, including the unrecoverable
    /// 401 one (BrowserModel) and a failed sign-in/2FA (`abortSignIn`).
    /// The remembered username survives only while "Keep me signed in"
    /// is on (F8.5 review).
    func signOut(reason: String? = nil) async {
        AppSettings.recordSignOut(in: defaults)
        await tearDown(reason: reason, keepRemembered: false)
    }

    /// The sign-out body. `keepRemembered` (only a network-failed restore)
    /// keeps the Keychain item and drops the session locally without the
    /// server-side revoke, so Retry can still use the refresh token.
    /// The cached Touch ID KEK goes either way (`delete` or `lock`).
    private func tearDown(reason: String?, keepRemembered: Bool) async {
        remembersSession = false
        canRetryRestore = false
        canRetryTouchID = false
        if keepRemembered {
            await vault.lock()
        } else {
            await vault.delete()
        }
        // F8.2-R5: download Tasks hold the coordinator, adapter and their
        // address-key copies — stop them (records land as "Cancelled")
        // before the keys are dropped below.
        await downloads?.cancelAll()
        // B12 / F8.2 review: stop the running uploads WITHOUT parking them
        // as user-paused — they continue when this account signs back in
        // (suspendForSignOut also detaches the uploader).
        await queue.suspendForSignOut()
        await queue.setUploader(nil)
        await uploads?.stop()
        // B12: hide the account's jobs until someone signs in again.
        await queue.setAccountScope(.signedOut)
        await resolver?.reset()
        resolver = nil
        listing = nil
        downloads = nil
        folderOps = nil
        uploads = nil
        roots = nil
        rootsError = nil
        if keepRemembered {
            await sessions.discard()
        } else {
            await sessions.signOut()
        }
        // Drop our seed references first so lock() can zero the last copy.
        addressKeys = []
        await keyrings.lock()
        clearPendingPassword()
        loginUsername = nil
        account = nil
        accountID = nil
        isVerifyingTwoFactor = false
        twoFactorError = nil
        loginError = reason
        phase = .signedOut
    }

    /// Fetches /core/v4/users + /core/v4/addresses for the account header.
    /// Cosmetic: a failure degrades to the typed username, never blocks login.
    func refreshAccount() async {
        do {
            let user = try await keyrings.fetchUser()
            let addresses = try await keyrings.fetchAddresses()
            let email = user.email ?? addresses.first?.email ?? loginUsername ?? ""
            account = Account(
                email: email,
                displayName: user.displayName ?? user.name ?? email,
                usedBytes: user.usedSpace ?? 0,
                maxBytes: user.maxSpace
            )
        } catch {
            guard account == nil, let loginUsername else { return }
            account = Account(email: loginUsername, displayName: loginUsername,
                              usedBytes: 0, maxBytes: nil)
        }
    }

    /// Fetches the classified drive roots for the shell. Runs when the phase
    /// enters .signedIn; a failure lands in `rootsError` (S2.1 renders it)
    /// and never reverts the sign-in. A sign-out mid-flight drops the result
    /// together with the listing that produced it (identity re-check).
    func loadRoots() async {
        guard let listing else { return }
        do {
            let loaded = try await listing.roots()
            guard self.listing === listing else { return }
            roots = loaded
            rootsError = nil
        } catch {
            guard self.listing === listing else { return }
            rootsError = UserFacingError.message(for: error)
        }
    }

    // MARK: - internals

    /// Password path: salts (needs the fresh password grant) → salted key
    /// password → the shared `finishUnlock`, then (F8.5) the remembered
    /// session if opted in — saved from the same buffer before it is wiped.
    private func finishSignIn() async throws {
        guard let pwd = pendingPassword else { throw ProtonAPIError.unauthorized }
        let user = try await keyrings.fetchUser()
        let primaryID = user.primaryKey?.id ?? ""
        var salted = try await sessions.fetchSaltedKeyPass(password: pwd, primaryKeyID: primaryID)
        // Password-equivalent: zeroed once the user keys are unlocked and
        // the vault has encoded its copy (or anything failed). Every other
        // reference (KeyringCache, the RememberedSession) is gone by then,
        // so the wipe hits the real bytes.
        defer { SecureBytes.wipe(&salted) }
        try await finishUnlock(saltedPass: salted, user: user)
        await rememberSessionIfEnabled(saltedPass: salted)
    }

    /// Unlock tail shared by password login and restore (F8.5): user keys
    /// → address keys → resolver + coordinators → queue scope. Seeds stay
    /// in the KeyringCache actor + `addressKeys` (memory only, never
    /// disk). Does not wipe `saltedPass` — its owner does. `user` skips a
    /// /users fetch when the caller already has it.
    private func finishUnlock(saltedPass: Data, user knownUser: ProtonUser? = nil) async throws {
        let user: ProtonUser
        if let knownUser {
            user = knownUser
        } else {
            user = try await keyrings.fetchUser()
        }
        let userKeys = try await keyrings.unlockUserKeys(saltedPass: saltedPass)
        addressKeys = try await keyrings.unlockAddressKeys(userKeys: userKeys)
        let resolver = NodeKeyResolver(source: drive, addressKeys: addressKeys)
        self.resolver = resolver
        listing = DriveListing(drive: drive, resolver: resolver)
        downloads = DownloadCoordinator(
            drive: drive, addressKeys: addressKeys, resolver: resolver,
            activity: activity
        )
        folderOps = FolderOperations(
            drive: drive, resolver: resolver,
            addressKeys: addressKeys, activity: activity
        )
        // S3.1: the coordinator wires the queue's live uploader + snapshot
        // listener for the whole session — jobs persist across sign-ins,
        // so start() also catches up `jobs`/`knownDone` from disk.
        let coordinator = UploadCoordinator(
            queue: queue, drive: drive, addressKeys: addressKeys,
            resolver: resolver, activity: activity
        )
        uploads = coordinator
        // B12: scope the shared queue to this account BEFORE the
        // coordinator wires the uploader — only its jobs show and run.
        // /users always carries ID; the username fallback only keeps a
        // malformed answer from mixing accounts.
        let owner = user.id ?? "username:" + (loginUsername ?? "").lowercased()
        accountID = owner
        await queue.setAccountScope(.account(owner))
        await coordinator.start()
    }

    /// Scrubs the retained password: SecureBytes (memset_s) zeroes the
    /// buffer BEFORE the last reference drops. Call sites run only after
    /// every `let pwd` copy is out of scope, and the property is cleared
    /// before the wipe, so `retained` uniquely owns the storage and the
    /// write hits the real bytes (Data is copy-on-write — zeroing a shared
    /// copy would silently scrub a detached buffer instead).
    private func clearPendingPassword() {
        guard var retained = pendingPassword else { return }
        pendingPassword = nil
        SecureBytes.wipe(&retained)
    }
}

#if DEBUG
extension AppSession {
    /// Preview seam: no disk persistence (queue storeURL nil), no network.
    /// `phase`/`account`/`roots`/`rootsError` are assigned directly — this
    /// same-file extension can write the `private(set)` fields — so shell
    /// previews can render signed-in, loading and error states offline.
    static func preview(
        phase: Phase = .signedOut,
        account: Account? = nil,
        roots: DriveRoots? = nil,
        rootsError: String? = nil,
        twoFactorError: String? = nil,
        canRetryRestore: Bool = false,
        canRetryTouchID: Bool = false
    ) -> AppSession {
        let session = AppSession(queueStoreURL: nil, vault: SessionVault(store: InMemoryKeychainStore()))
        session.phase = phase
        session.twoFactorError = twoFactorError
        session.canRetryRestore = canRetryRestore
        session.canRetryTouchID = canRetryTouchID
        session.account = account
        session.roots = roots
        session.rootsError = rootsError
        return session
    }

    /// Offline demo session for QA agents and screenshots: signed-in shell
    /// over DemoDriveListing, no network, no keys. Launch with `-NTDemoMode
    /// YES`. resolver/coordinators stay nil so the write UI is disabled, and
    /// `roots` loads through the normal `loadRoots()` path.
    static func demo() -> AppSession {
        let session = AppSession(queueStoreURL: nil, vault: SessionVault(store: InMemoryKeychainStore()))
        session.phase = .signedIn
        session.account = Account(
            email: "demo@example.com", displayName: "Demo",
            usedBytes: 2_150_000_000, maxBytes: 5_000_000_000
        )
        session.listing = DemoDriveListing()
        Task { await session.loadRoots() }
        return session
    }

    /// True while the session is backed by the offline demo listing —
    /// sign-out nils `listing`, so the flag clears itself.
    var isDemo: Bool { listing is DemoDriveListing }
}
#endif
