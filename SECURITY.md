# SECURITY — Nucleon Transfer

## Reporting a vulnerability

- Open a private issue / contact the maintainer (channel to be defined on
  the repo). Do not open a public issue with an exploitable PoC before a
  fix ships.
- Include: version (`0.1.0-alpha` + commit), macOS version, minimal steps,
  impact, redacted logs.
- Best-effort alpha SLA: triage within 7 days. No bug bounty at this stage.

## Never do

- Never commit credentials, tokens, `otp_secret`, private keys or session
  dumps.
- Never paste `AccessToken` / `RefreshToken` / `clientProof` / session keys
  into issues, logs or screenshots.
- Never log the password, SRP secrets (`S`, `K`, `M1`) or unwrapped keys.
  Logs carry IDs and truncated prefixes only.

## How secrets are handled

- **Nothing secret on disk by default:** the session (tokens) and
  unlocked key seeds live in actors in memory and die on sign-out/quit.
  Nothing secret in UserDefaults, SwiftData or plists (UserDefaults holds
  preferences and the last username only).
- **"Keep me signed in" (opt-in, off by default)** writes ONE Keychain item
  (`RememberedSession` v1): UID, refresh token, salted key password,
  username, timestamp. Never the password, SRP values, the access token or
  unlocked keys. Data-protection keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  `kSecAttrSynchronizable = false` (never iCloud), app keychain access
  group only. Threat model: while it is on, someone using your unlocked
  Mac — or code running as you with access to this app's keychain group —
  can resume the session; the salted key password unlocks your Drive keys
  (it is not your account password). Changing the Proton password
  invalidates both.
- **"Require Touch ID" (opt-in)**: the blob is sealed with AES-256-GCM
  under a random key (KEK) stored in a second item protected by
  `SecAccessControl(.biometryCurrentSet)` — Touch ID with a currently
  enrolled finger, no passcode fallback. Enrolling/removing a fingerprint
  invalidates the KEK; the app then deletes both items and asks for the
  password. The KEK is held in memory for the session (token rotation
  re-seals without a prompt) and dropped on sign-out.
- Settings › Account › **Forget This Mac** deletes both items and the
  remembered username. Design and failure semantics:
  `docs/DECISIONS/ADR-004-remember-me.md`.
- The password is kept as `Data` only between sign-in and the post-2FA key
  unlock; that buffer is zeroed (`memset_s` via `SecureBytes`, before the
  last reference drops) on every exit path — success, error, cancel,
  sign-out.
- Zeroing is **best-effort**. The app wipes buffers it owns once they are
  used: bcrypt key schedule and password copy, the SRP password hash, the
  salted key password, decrypted key passphrases, S2K keys, secret-key
  plaintext, and cached key seeds on sign-out. It cannot wipe the
  password field's Swift `String`, copies the runtime makes on its own,
  CryptoKit key objects, or `Data` still shared with another live value
  (copy-on-write) — those are released to the allocator, not zeroed.
- `AccessToken` lives only in the `SessionManager` actor; refresh runs on
  demand after a 401 and is single-flight (one shared refresh, rotated
  tokens reused). A session epoch stops a refresh that finishes after
  sign-out from writing the session back. HTTP redirects are followed only
  to the same https host.
- **Sign-out order:** delete the remembered-session Keychain items (if
  any) → cancel downloads → pause + detach the upload queue → wipe the
  `NodeKeyResolver` (all cached node/share seeds) → drop listing and
  coordinators → `DELETE /auth/v4` (server-side session revocation,
  best-effort — local sign-out always wins) → lock the `KeyringCache` →
  clear UI-visible state.
- The only persisted file is the upload queue snapshot
  (`transfer-queue.json`: paths, link IDs, progress) — verified to contain
  no secrets. The only persisted secrets are the opt-in Keychain items
  above.
- Security-scoped bookmarks for upload/download folders; no sensitive
  absolute paths in logs.

## Telemetry

- None. Zero analytics, zero third-party crash reporters.
- No data leaves the Mac beyond official Proton Drive API calls carrying
  the header `x-pm-appversion: external-drive-nucleon_transfer@0.1.0-alpha`.

## Relevant surface

- Native SRP-6a; unlock chain User→Address→Share→Node→Session; AES-CFB +
  SHA-256 + MDC per block (SED/SEIPDv1 packets).
- Breaking crypto migration expected end of 2026 / early 2027: the crypto
  layer is isolated for a clean swap — no persisted key material to
  migrate (the opt-in remembered session holds tokens and the salted key
  password, which a re-login regenerates).
- HV 9001: pauses the queue; never bypassed automatically.
- The app never spoofs another client's identity, even where the server
  would accept it (the block-upload allowlist rejects our honest
  identifier — uploads stay disabled rather than spoofed; see
  `docs/TRANSFERS.md` §9).
