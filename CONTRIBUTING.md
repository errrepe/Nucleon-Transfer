# CONTRIBUTING — Nucleon Transfer

## 1. Principles

- Native macOS SwiftUI, Swift 6 strict concurrency. No new warnings.
- Official endpoints only + header
  `x-pm-appversion: external-drive-nucleon_transfer@0.1.0-alpha` on every call.
- No Proton logos, no claim of official support. Keep the third-party
  disclaimer wherever credentials are requested.
- Docs before code on architectural changes (update `docs/` + an ADR if it
  is a decision).

## 2. Swift style

- Follow the neighboring file's indentation (Xcode defaults).
- `Sendable`, `actor` wherever state is shared. No `try!` / `fatalError`
  on production paths (only in `precondition` for impossible invariants).
- Naming: `SessionManager`, `DriveClient`, `UploadEngine`,
  `DownloadEngine`, `TransferStore`-style. Protocols used for mocking get
  descriptive names.
- UI: thin views, logic in `@Observable` view-models. No networking in
  `View.body`.

## 3. Issues / PRs

- Open an issue before a large PR. Reference the phase in
  `docs/ROADMAP.md`.
- Small PRs, one topic each, including: what, why, how it was tested
  (build + `swift test`), docs updated.
- Any PR touching crypto or networking must cite the test vectors or the
  test account used (never credentials).

## 4. Tests

- Offline suite `NucleonTransferTests` (Swift Testing): RFC vectors
  (AES-KW §4.1), integers vs Python, bcrypt vs the reference C
  implementation, S2K/KDF/ECDH synthetic interop, Ed25519 roundtrip,
  fingerprints. No network, no secrets — always safe to run.
- Local loop: `swift test` at the **repo root**. The root `Package.swift`
  compiles `NucleonTransfer/NucleonTransfer/Core/` as module
  `NucleonTransfer` plus the `NucleonTransferTests/` suite — no Xcode, no
  scheme.
- The `NucleonTransferTests` target in the `.xcodeproj` is not hosted by
  the app (no `TEST_HOST`), so `@testable import` does not link under
  Xcode — `swift test` is the canonical path for the offline suite (the
  shared `NucleonTransfer` scheme deliberately lists no testables).
- **Demo mode (DEBUG only):** launch the app signed into an offline,
  deterministic drive — no credentials, no network. In Xcode: Product →
  Scheme → Edit Scheme → Run → Arguments → add `-NTDemoMode YES`. Via
  cua-driver: `launch_app` with
  `additional_arguments: ["-NTDemoMode","YES"]`. The sidebar footer shows a
  "Demo Mode" capsule; Sign Out returns to the normal login screen.

### Benchmarks

- `Benchmarks/` is a separate SwiftPM package (not part of `swift test`):
  `Sources/NucleonCore` is a symlink to `NucleonTransfer/NucleonTransfer/Core`,
  compiled with `-enable-testing` so `nucleon-bench` reaches internal API.
- Run in release (debug numbers are meaningless):
  `swift run -c release --package-path Benchmarks nucleon-bench [filter]`
  — `filter` is a substring of the case name (e.g. `upload`, `bcrypt`).
- Cases: FileUpload block encrypt/decrypt (4 MiB), armored message decrypt
  (4 MiB), `BigUInt.modPow` 2048-bit, bcrypt cost 10,
  `TransferQueue.enqueueTree` of 3k files, `DriveItemOrdering` filter+sort.
  Each prints the median and min of N runs after a warm-up.
- Performance PRs paste before/after numbers from this harness.

## 5. Git

- No CI — there are no GitHub workflows or gates.
- Do not commit unless explicitly asked. Do not push unless asked.
- Never commit secrets, tokens, session dumps, `.sqlite`, `DerivedData`,
  `.build`.

## Maintainer setup

Notes specific to this maintainer's machine and workflow — not required to
contribute.

- **Shell prefix `rtk`:** every shell command is prefixed with `rtk`
  (Rust Token Killer proxy). Examples: `rtk git status`, `rtk swift test`,
  `rtk ls`. Meta: `rtk gain`, `rtk gain --history`.
- **Xcode MCP workflow:** always drive Xcode through the MCP tools
  (`XcodeRead`, `BuildProject`, `RunSomeTests`, `RenderPreview`, …).
  Discover targets/schemes with the listing tools before building. Prefer
  MCP over creating projects from the command line. Leave no hung
  processes (`StopProject` after verifying on a device/simulator).
- **DerivedData on the external SSD:** on any `db lock` / DerivedData
  error, always point it to `/Volumes/SSD 4TB/DEV/DerivedData` — never the
  Mac's internal SSD.
- **No concurrent builds:** if a build is running in the background, wait
  before launching another.
- **Live verification spacing:** there is no Keychain, so every live check
  needs a fresh login — space SRP logins ~11 minutes apart (rate-limit
  2028) and batch everything into ONE battery per login. Credentials only
  via env (`NT_USER`/`NT_PASS`), never on disk. Probe packages live under
  `/private/tmp` (e.g. `nt-f6live`); see `docs/DEVLOG.md` for the F6
  battery. Xcode `RunCodeSnippet` has a ~5s watchdog — use the CLI probe
  with `-O` for long flows (SRP ~20s debug).
