// Nucleon Transfer — session root: single DI container + auth lifecycle (F7).
// Owns the ONLY SessionManager / KeyringCache / DriveClient / TransferQueue /
// TransferActivityStore; views read them via .environment (injected at the
// WindowGroup). Secrets stay inside the owning actors, memory only; the
// password is retained as Data solely between signIn and the post-2FA key
// unlock, and that buffer is zeroed on every path (success, error, cancel,
// sign-out). Best-effort: the String the login field handed over, and any
// copy the runtime made, cannot be wiped (F8.1-S7).
import Foundation

@MainActor
@Observable
final class AppSession {
    enum Phase: Equatable {
        case signedOut
        case signingIn      // SRP handshake in flight
        case needsTwoFactor // TOTP required; password retained for post-2FA unlock
        case unlocking      // session OK; decrypting key hierarchy (salts → user → address)
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

    let activity = TransferActivityStore()
    let queue: TransferQueue
    let sessions: SessionManager
    let keyrings: KeyringCache
    /// The ONLY DriveClient in the app — features share this instance.
    let drive: DriveClient

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

    init(queueStoreURL: URL? = TransferQueue.defaultStoreURL()) {
        let sessions = SessionManager()
        self.sessions = sessions
        keyrings = KeyringCache(sessions: sessions)
        drive = DriveClient(sessions: sessions)
        // B12: nothing in the shared snapshot is visible or runnable until
        // an account signs in (finishSignIn scopes the queue to it).
        queue = TransferQueue(storeURL: queueStoreURL, accountScope: .signedOut)
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
        await refreshAccount()
        phase = .signedIn
        await loadRoots()
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

    /// Sign-out order (S0.3): cancel in-flight downloads and pause + detach
    /// the upload queue BEFORE dropping auth, revoke the session
    /// server-side (best-effort), wipe key seeds, then reset UI-visible
    /// state. `reason` lands on the login screen.
    func signOut(reason: String? = nil) async {
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
        await sessions.signOut()
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

    /// Salts → user keys → address keys, while the password grant is fresh
    /// (moved from LoginViewModel, semantics unchanged). Seeds stay in the
    /// KeyringCache actor + `addressKeys` (memory only, never disk).
    private func finishSignIn() async throws {
        guard let pwd = pendingPassword else { throw ProtonAPIError.unauthorized }
        let user = try await keyrings.fetchUser()
        let primaryID = user.primaryKey?.id ?? ""
        var salted = try await sessions.fetchSaltedKeyPass(password: pwd, primaryKeyID: primaryID)
        // Password-equivalent: zeroed once the user keys are unlocked (or
        // the unlock failed). KeyringCache's copy is gone by then.
        defer { SecureBytes.wipe(&salted) }
        let userKeys = try await keyrings.unlockUserKeys(saltedPass: salted)
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
        twoFactorError: String? = nil
    ) -> AppSession {
        let session = AppSession(queueStoreURL: nil)
        session.phase = phase
        session.twoFactorError = twoFactorError
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
        let session = AppSession(queueStoreURL: nil)
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
