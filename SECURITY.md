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

- **Nothing secret on disk:** the session (tokens) and unlocked key seeds
  live in actors in memory and die on sign-out/quit. Nothing in
  UserDefaults, SwiftData or plists. No Keychain — re-login on every
  launch, like the official app.
- The password exists as `Data` only between sign-in and the post-2FA key
  unlock; its buffer is zeroed (`resetBytes` before the reference drops)
  on every exit path — success, error, cancel, sign-out.
- `AccessToken` lives only in the `SessionManager` actor; refresh runs on
  demand after a 401 and is single-flight (one shared refresh, rotated
  tokens reused). A session epoch stops a refresh that finishes after
  sign-out from writing the session back. HTTP redirects are followed only
  to the same https host.
- **Sign-out order:** pause + detach the upload queue → wipe the
  `NodeKeyResolver` (all cached node/share seeds) → drop listing and
  coordinators → `DELETE /auth/v4` (server-side session revocation,
  best-effort — local sign-out always wins) → lock the `KeyringCache` →
  clear UI-visible state.
- The only persisted file is the upload queue snapshot
  (`transfer-queue.json`: paths, link IDs, progress) — verified to contain
  no secrets.
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
  layer is isolated for a clean swap — nothing persisted to migrate, all
  in memory.
- HV 9001: pauses the queue; never bypassed automatically.
- The app never spoofs another client's identity, even where the server
  would accept it (the block-upload allowlist rejects our honest
  identifier — uploads stay disabled rather than spoofed; see
  `docs/TRANSFERS.md` §9).
