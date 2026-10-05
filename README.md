<p align="center">
  <img src="assets/app-icon.png" width="160" alt="Nucleon Transfer icon">
</p>

# Nucleon Transfer

Nucleon Transfer is a native macOS client for Proton Drive focused on what the
official app does not offer: browsing your Drive, uploading arbitrary files and
folders via drag-and-drop with structure preserved, and downloading to a folder
you choose. It implements SRP login, the full key-hierarchy unlock and the
OpenPGP block format in pure Swift — end-to-end encryption is done on this Mac,
exactly like the official clients. (Note: uploads are currently blocked by a
server-side allowlist — see Known limitations.)

> Nucleon Transfer is an independent, open-source app. It is not affiliated
> with or endorsed by Proton AG. Your password is used only to sign in and
> unlock your keys on this Mac — it is never stored.

<!-- TODO(maintainer): capture docs/images/main-window.png before release -->

## Status

`0.1.0-alpha`. All crypto, networking and the native UI are implemented and
verified; the offline test suite is green (`swift test`, 565 tests). This is an
alpha: expect rough edges and read the known limitations below.

## Features

- **Sign in** with your Proton account (SRP-6a), two-factor with an
  authenticator code or a recovery code, automatic session refresh.
- **Browse** My Files, Photos (read-only) and Computers in a native
  `NavigationSplitView` + `Table` browser: navigate folders with
  Back/Forward, an optional path bar, sortable Name/Kind/Size/Modified
  columns, filter, multi-select; the window remembers its folder, columns
  and sort.
- **New Folder** and **Move to Trash** from the toolbar, context menu or
  keyboard.
- **Upload** files and folders by dropping them on the table or via the
  Upload menu — recursive, hierarchy-preserving, resumable queue with
  pause / cancel / retry and a Transfers popover with speed and time left.
- **Download** selected files and folders via the system picker or
  straight to a default folder — several at once, each cancellable,
  mirrors the remote tree, verifies SHA-256 per block, atomic writes.
- **Settings**: default download folder, simultaneous uploads/downloads,
  open Transfers on start, ask before moving to Trash.
- **Localized** in English and Brazilian Portuguese (pt-BR) via a String
  Catalog (`Resources/Localizable.xcstrings`); the app follows the macOS
  language setting.
- All listing, decryption and transfers run off the main thread in actors.

## Requirements

- macOS 26.0 or later.
- A Proton account with Drive provisioned (open drive.proton.me once in a
  browser to create your vault if you never used Proton Drive).
- To build from source: Xcode 26 and a Swift 6.2 toolchain.

## Build from source

```sh
git clone <repo-url>
cd "Nucleon Transfer"
open NucleonTransfer/NucleonTransfer.xcodeproj
```

Build and run the `NucleonTransfer` scheme. There are no third-party
dependencies.

To run the offline test suite (pure Foundation, no Xcode required):

```sh
swift test
```

The root `Package.swift` compiles `NucleonTransfer/NucleonTransfer/Core/`
plus `NucleonTransfer/NucleonTransferTests/` directly.

## Security model

- **Memory only.** Access/refresh tokens, the salted key password, unlocked
  keys and session seeds live in actors in memory. Nothing is written to
  Keychain, UserDefaults or plists — signing in again is required on every
  launch, like the official app.
- The password is kept as `Data` only between sign-in and the key unlock,
  and that buffer is zeroed on every exit path (success, error, cancel,
  sign-out). Buffers the app owns — bcrypt state, the password hash, the
  salted key password, decrypted key passphrases and cached key seeds —
  are zeroed **best-effort** once used. Swift cannot guarantee the same for
  copies the runtime makes (the password field's `String`, CryptoKit key
  objects, buffers still shared with other live values): those are
  dropped, not wiped.
- **Sign-out** revokes the session server-side (`DELETE /auth/v4`,
  best-effort) and drops all in-memory key material, zeroing what it owns.
- **On disk:** only the upload queue (`transfer-queue.json` under
  Application Support) — paths, IDs and progress, no secrets.
- No telemetry, no analytics, no third-party crash reporters.
- Every request sends an honest `x-pm-appversion:
  external-drive-nucleon_transfer@0.1.0-alpha` header — the app never
  impersonates another client.

See `SECURITY.md` for reporting and `docs/ARCHITECTURE.md` for internals.

## Known limitations (alpha)

- **Uploads are currently blocked server-side.** Proton's block-upload
  endpoint enforces an app-version allowlist and rejects our honest client
  identifier (error 2000). The full upload pipeline (folder creation,
  encryption, queue, UI) is implemented and tested, but direct uploads fail
  with an actionable error in this alpha. Downloads work normally. We will
  not spoof another client's identifier — see `docs/TRANSFERS.md` §9.
- Whole files are buffered in memory during upload (streaming is planned).
- Displayed sizes are the encrypted sizes; real sizes live in per-file
  metadata not yet decrypted.
- No live sync: listings refresh on demand and after local operations —
  event-based sync is on the backlog.
- No trash view, no rename, no Shared section, generic computer names.

The full backlog lives in `docs/plans/F7-NATIVE-UI.md` §9.

## Third-party rules

This app follows Proton's rules for third-party clients: official endpoints
only, the honest identification header above, no polling (event sync is on
the backlog), clear disclosure that it is a third-party app wherever
credentials are requested, and no Proton logos or branding.

## Docs

- `docs/ARCHITECTURE.md` — layers, actors, concurrency
- `docs/AUTH.md` — SRP flow, 2FA, refresh, session, errors
- `docs/TRANSFERS.md` — upload / download engines in detail
- `docs/SDK-STRATEGY.md` — why native Swift instead of an SDK binding
- `docs/ROADMAP.md` — phases F0–F7
- `docs/DECISIONS/` — ADRs
- `docs/DEVLOG.md` — development history
- `CONTRIBUTING.md` — how to contribute
- `SECURITY.md` — reporting and secret handling

## Contributing

Open source under MIT. See `CONTRIBUTING.md` and `LICENSE`.

1. Read `docs/ARCHITECTURE.md`, `docs/AUTH.md`, `docs/TRANSFERS.md`.
2. Check `docs/ROADMAP.md` for the current phase.
3. Open an issue before large PRs.

## License

MIT — see `LICENSE`. Copyright 2026 Nucleon Transfer contributors.
