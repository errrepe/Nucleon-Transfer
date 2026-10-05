# ADR-004 — "Keep me signed in": refresh token in the Keychain, optional Touch ID

- Status: Accepted
- Date: 2026-10-05
- Context: the 2026-10-04 audit (`docs/AUDIT-2026-10-04.md`, "Login
  salvo") asked for an opt-in way to skip the password on relaunch. Until
  now the app kept every secret in memory only and promised "no Keychain"
  (README, SECURITY.md, AUTH.md); every launch was a full SRP login with
  bcrypt, 2FA and Proton's 2028 login rate limit. Prerequisites from the
  audit were in place first: single-flight refresh with a session epoch
  (P0-5) and fail-closed signature checks (P0-2). Implemented in F8.5
  (slices V1–V3, branch `feat/f8-5-remember-me`).

## Decision

Opt-in, off by default, at two levels: "Keep me signed in" (login
checkbox and Settings › Account) and, on top of it, "Require Touch ID"
(Settings › Account).

### What is stored

One versioned blob, `RememberedSession` v1 (JSON):

| Field | Why |
|---|---|
| `uid`, `refreshToken` | resume the session with `POST /auth/v4/refresh` |
| `saltedKeyPass` | a restored session has no password scope for `/core/v4/keys/salts`, and the user keys need it to unlock. It is password-equivalent **for the keys** (not for the account login) |
| `username`, `savedAt` | login prefill, diagnostics |

Never stored: the password, SRP values, the access token, unlocked keys or
key seeds. `RememberedSession.description` is redacted.

### Where, and with which attributes

- Generic-password items in the **data-protection keychain**
  (`kSecUseDataProtectionKeychain = true`), service `<bundle id>.session`.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: readable only while the
  Mac is unlocked, never in backups that migrate to another device.
- `kSecAttrSynchronizable = false`: never in iCloud Keychain.
- Entitlement `keychain-access-groups =
  [$(AppIdentifierPrefix)dev.nucleon.NucleonTransfer]` (the data-protection
  keychain requires one). No `kSecAttrAccessGroup` in queries: with a
  single group, SecItemAdd defaults to it.
- Accounts: `remembered-session.v1` (the blob) and, in Touch ID mode,
  `remembered-session.kek.v1` (the key-encryption key).

### Touch ID mode (KEK design)

- A random 256-bit KEK (`SymmetricKey(size: .bits256)`) is stored in its
  own item with `SecAccessControl(kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  .biometryCurrentSet)` — Touch ID with a currently enrolled finger, **no
  passcode fallback**. Enrolling or removing a fingerprint invalidates the
  item permanently.
- The blob item then holds `"NTSEAL\x01" ‖ AES-GCM(nonce ‖ ciphertext ‖
  tag)` of the JSON, with the marker as associated data. The marker lets
  the vault tell sealed from plain (`{`) blobs; anything else is deleted.
- Only the launch restore (and turning Touch ID off without the key in
  memory) reads the KEK item, in two steps: `LAContext.evaluatePolicy`
  (async, off the vault actor — the prompt never blocks a thread) with a
  localized reason ("Nucleon Transfer is trying to unlock your saved
  sign-in") and no password fallback button, then a non-interactive
  `SecItemCopyMatching` with that authenticated context. Classification
  (`BiometricRead.classify`): evaluation cancelled → cancelled; no finger
  enrolled → invalidated; other evaluation failure / lockout →
  unavailable; evaluation succeeded but the read answers
  `errSecItemNotFound` or `errSecAuthFailed` → invalidated (the item's
  enrolled-finger snapshot is gone — never an endless "try again").
  Concurrent unlocks share one prompt; a KEK that arrives after the items
  changed is discarded. Every other read uses `interactionNotAllowed` and
  can never show UI.
- The KEK stays in the `SessionVault` actor for the session, so each
  refresh-token rotation re-seals the blob without prompting again. It is
  dropped on sign-out and when a restore fails; CryptoKit releases (and
  zeroes) its storage. Its raw bytes in transient `Data` are wiped
  best-effort.
- Switching "Require Touch ID" re-seals or unseals the stored session in
  place; on a Mac where `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
  is false the toggle is disabled. If Touch ID is required but unavailable
  at sign-in time (lid closed, no finger enrolled), nothing is stored —
  never a silent plain copy.

### Failure semantics

| Situation | Items | User sees |
|---|---|---|
| Network failure during restore (offline, timeout, 5xx, 429) | kept | "Couldn't reach Proton…" + Try Again |
| Refresh token rejected, 401, key unlock or signature failure, malformed answer | deleted | "Your saved sign-in has expired…" |
| Touch ID cancelled, or not available right now (lid closed, lockout) | kept | password login + "Use Touch ID" |
| Fingerprints changed, KEK missing or wrong size, blob won't unseal / decode | both deleted | "Your Touch ID fingerprints changed…" |
| Any unknown Keychain read error on the blob | treated as absent | password login |

Pure and unit-tested in `RestoreFailure` and `SessionVault`. The policy is
biased toward deleting: an unknown failure never leaves a secret behind,
and a successful password login always rewrites (or removes) both items.

### Lifecycle and sign-out order

1. Password login (incl. 2FA) → key unlock → if "Keep me signed in" is on,
   the blob is saved (sealed when Touch ID is required); otherwise any
   item is deleted.
2. Launch (once per app launch, and only while "Keep me signed in" is on —
   otherwise any leftover item is deleted) → `.restoring`: Touch ID
   (sealed only) → `restore(uid:refreshToken:)`
   (refresh **without** an access token) → the same `finishUnlock` as a
   password login with the stored salted key password.
3. Every token rotation is written through to the item, but only while it
   belongs to the live session; a refresh never creates an item. Changes
   travel on `SessionManager.tokenChanges` (an ordered AsyncStream yielded
   on the actor); one AppSession task writes the *current* token for each
   event, so the refresh never waits for Keychain I/O and a late event
   can't roll the item back.
4. The last username (login prefill, UserDefaults) is kept only with
   "Keep me signed in": saved at a sign-in with it on, cleared at a
   sign-in or sign-out with it off. Both "Keep me signed in" toggles
   (login checkbox, Settings) go through one `AppSession.setKeepSignedIn`,
   which deletes the items when it is switched off.
5. **Sign-out deletes both items first** — before any network call and
   before keys are dropped — then cancels transfers, revokes the session
   server-side (best-effort), wipes key material.
6. Settings › "Forget This Mac" deletes both items and the remembered
   username without ending the current session.

## Alternatives rejected

- **Store the password** (and redo SRP each launch): the password unlocks
  the whole Proton account, not just the keys; it also re-triggers 2FA and
  the 2028 login rate limit. Rejected outright.
- **File-based (legacy) login keychain**: per-app ACLs prompt with the
  user's macOS password, behave badly with ad-hoc / re-signed builds, and
  have no `ThisDeviceOnly` or biometric access control. The
  data-protection keychain is Apple's recommended store on macOS.
- **Synchronizable (iCloud Keychain) items**: a refresh token is a bearer
  credential — copying it to every device of the Apple ID widens the blast
  radius, and rotation across devices would race (Proton invalidates a
  spent refresh token).
- **Always-on remembering / always-on Touch ID**: changes the threat model
  for users who chose this app because it stored nothing; it stays opt-in.
  Touch ID mandatory would exclude Macs without a sensor.
- **Biometry with passcode fallback** (`.userPresence`): equates "Touch
  ID" with the Mac login password; rejected so the toggle means what it
  says. Users can always fall back to the Proton password.

## Consequences

- A stolen, unlocked Mac (or malware running as the user with keychain
  access to this app's group) can resume the Proton session and decrypt
  Drive data while "Keep me signed in" is on — unless Touch ID is
  required. This is documented in SECURITY.md and is the user's choice.
- The salted key password on disk is a key-unlock credential; changing the
  Proton password invalidates it (and the refresh token), and the next
  restore falls back to the password login.
- The app now needs a provisioning profile for the keychain access group
  (automatic signing with the team in `DEVELOPMENT_TEAM`).
- Zeroing stays best-effort: decoded `String`s (tokens, username) cannot
  be wiped; owned `Data` buffers are.
- Touch ID outcomes depend on Keychain status codes that only real
  hardware produces; they are classified by pure functions and covered by
  fakes, with live checks listed in the F8.5 PR.
