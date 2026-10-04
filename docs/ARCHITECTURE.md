# ARCHITECTURE — Nucleon Transfer

> Status: alpha. Native macOS 26 SwiftUI, Swift 6 strict concurrency.
> Reflects the real tree after F7 (2026-10-02).

## 1. Goals

- Arbitrary upload via drag-and-drop preserving folder structure.
- Download to a user-chosen folder via the system picker.
- Transfer queue with progress / pause / cancel / retry.
- Interop with Proton Drive via official endpoints only.
- Crypto isolated for the breaking migration expected end of 2026 / early 2027.

## 2. Real tree

```
NucleonTransfer/NucleonTransfer/
  App/
    NucleonTransferApp.swift    — entry point: Window + Settings + commands
    AppSession.swift            — @MainActor @Observable DI root + auth lifecycle
    RootView.swift              — login ↔ main switch by session phase
    AppCommands.swift           — menubar commands (New Folder, Upload, Download…)
  Core/                         — pure Foundation; compiled by root Package.swift
    Crypto/
      SRPClient.swift, BigUInt.swift, PasswordHash.swift, ExpandHash.swift,
      ModulusDecoder.swift, UsernameCleaner.swift
      BCrypt/                   — Proton bcrypt (EksBlowfish) for the key password
      PGP/                      — packets, SED/SEIPD encrypt+decrypt, ECDH,
                                  AES-KW, armor, detached sign/verify, NodeKeyGen
    ProtonAPI/
      APIClient.swift           — URLSession wrapper, auth calls, authDelete,
                                  raw block download (octet-stream)
      SessionManager.swift      — actor: session tokens, refresh single-flight,
                                  signOut → DELETE /auth/v4
      DriveClient.swift         — actor: Drive endpoints (shares/links/children,
                                  files, folders, trash, revisions, block upload)
      AuthModels.swift, DriveModels.swift,
      KeyMaterial.swift         — key payloads + ProtonUser/addresses
      FileUpload.swift          — draft + blocks + commit pipeline
      FolderCreate.swift        — folder envelope + key material
      ProtonAPIError.swift, AppVersion.swift
    Security/
      KeyringCache.swift        — actor: user/address key unlock, memory only
      DecryptChain.swift        — Share→Node→Session decrypt chain
      NodeKeyResolver.swift     — actor: single-flight key resolution under any
                                  remote folder; reset() wipes everything
    Drive/                      — pure models + listing
      DriveRoot.swift           — root classification (My Files/Photos/Computers)
      DriveItem.swift, DriveItemOrdering.swift, DriveLocation.swift,
      DriveFormatting.swift, ShareKind.swift, FolderNameValidator.swift
      DriveListing.swift        — actor: children(of:) → [DriveItem]; name
                                  decryption runs off-main via resolver
    Transfers/
      TransferQueue.swift       — actor: upload queue, JSON snapshot persistence
      LocalTreeScan.swift       — recursive intake (detached task)
      DriveUploadAdapter.swift, DriveDownloadAdapter.swift — live bridges
      FileDownload.swift        — verify + reassemble + atomic write
      DownloadRecord.swift, TransferDisplay.swift, UserFacingError.swift,
      PanelIntake.swift
  Features/
    Auth/       LoginView, TwoFactorView, UnlockingView
    Shell/      MainView, SidebarView (+ SidebarItem), StorageFooterView
    Browser/    BrowserModel, BrowserContainerView (NavigationStack per root),
                FolderView, FolderTable, FileIcon, NewFolderSheet,
                FolderOperations (create/trash), DropOverlay
    Transfers/  TransferActivityStore, UploadCoordinator, DownloadCoordinator,
                TransfersToolbarButton, TransfersPanel, TransferRow
    Settings/   SettingsView
    Shared/     Panels (async NSOpenPanel)
    Preview/    PreviewFixtures (#if DEBUG)
NucleonTransfer/NucleonTransferTests/   — Swift Testing suite (171 tests)
```

Rules:

- `Features` never touch `URLSession` — only `DriveClient` / coordinators / engines.
- `Core` imports Foundation only — no SwiftUI, no AppKit. Testable via SPM.
- `Core/Crypto` knows nothing about UI or network; interfaces stay injectable
  for the crypto migration.
- `AppSession` is the only DI root; views get it via `.environment`.

## 3. AppSession (@MainActor DI root)

One instance owns the session lifetime:

```
AppSession
 ├─ sessions: SessionManager (actor)   — tokens, refresh, DELETE /auth/v4
 ├─ keyrings: KeyringCache (actor)     — user/address unlock, memory only
 ├─ drive: DriveClient (actor)         — THE one client instance
 ├─ resolver: NodeKeyResolver? (actor) — created post-unlock, reset+dropped on sign-out
 ├─ listing: DriveListing? (actor)     — drive + resolver glue
 ├─ queue: TransferQueue (actor)       — created at init, JSON-persisted
 ├─ activity: TransferActivityStore (@MainActor @Observable)
 ├─ uploads / downloads / folderOps    — coordinators created post-unlock
 ├─ roots: DriveRoots?                 — My Files / Photos / Computers
 └─ account: Account?                  — email, display name, quota
```

The password is kept as `Data` only between `signIn` and the post-2FA
unlock (`pendingPassword`), and that buffer is zeroed on every exit path
(`clearPendingPassword` — `SecureBytes.wipe` before the last reference
drops). Other owned secret buffers are zeroed best-effort too; the login
field's `String` and runtime copies cannot be (see SECURITY.md).

Sign-out order: pause queue + detach uploader → `resolver.reset()` → drop
resolver/listing/coordinators → `sessions.signOut()` (local clear, then
best-effort `DELETE /auth/v4`) → drop `addressKeys` → `keyrings.lock()`
→ wipe UI state.

## 4. NodeKeyResolver (actor)

Single point of key resolution for share/node material under ANY remote
folder. Single-flight: concurrent requests for the same node share one
in-flight task (cleaned via `defer`). Memory only; `reset()` wipes all
cached seeds. Used by `DriveListing` (name decryption), both transfer
adapters and `FolderOperations`.

## 5. DriveListing (actor)

`children(of: location) -> [DriveItem]` — fetches links/children, resolves
node keys via the resolver, decrypts names OFF the main thread, returns
sorted pure-Swift models for the `Table`. Also classifies roots
(`roots() -> DriveRoots`).

## 6. TransferQueue — JSON, not SwiftData

The upload queue is an actor owning a `Codable` snapshot persisted
atomically to `Application Support/NucleonTransfer/transfer-queue.json`.
Rationale: an actor + snapshot has fewer failure modes than a `@Model`
graph + `ModelContext`. The snapshot holds paths/IDs/progress only — never
secrets (enforced by `snapshotHoldsNoSecrets`). `uploading` → `queued` on
load. Concurrency: 3 parallel upload slots, sequential blocks per job,
backoff `min(60s, 1s·2^(n-1)) + jitter`, HV 9001 → `pauseAll()`.

Downloads run through a dedicated `DriveDownloadAdapter` + lightweight
`DownloadRecord`s reported to `TransferActivityStore` (in-memory history,
no persistence) — uploads and downloads appear together in the Transfers
popover.

## 7. Crypto — three isolated blocks

### 7.1 SRP (`SRPClient`)

SRP-6a pure Swift (BigUInt + SHA256 + HMAC). `POST /auth/v4/info` →
`clientEphemeral`/`clientProof` → `POST /auth/v4`. Validated against
`go-proton-api`/`rclone` vectors + live login.

### 7.2 KeyHierarchy (`KeyringCache` / `DecryptChain`)

```
User key (bcrypt key password)
  → Address keys → Share keys → Node keys → Session keys (per block/file)
```

Each level decrypts the next; failure at any level is a typed error, never
a crash, never a logged key.

### 7.3 MessageCrypto + BlockCrypto

- Decrypt: `MessageDecrypt` (PKESK v3/ECDH) + `SEDDecrypt` (tag 9 resync /
  tag 18 v1 + MDC) + fingerprints — verified against RFC vectors + GnuPG
  interop.
- Encrypt (upload mirror): `ECDHEncrypt` + `SEDEncrypt` + `LiteralPacket`
  + `Armor`; `MessageEncrypt.encryptSigned` for names, `DetachedSign` for
  passphrases/blocks. Live-verified signature conventions (notation salt,
  issuer-fingerprint, OPS nested=0x01).
- Block format: SED tag-18 packets, 4 MiB default (`FileUpload.defaultBlockSize`).
  Block `Hash` = base64(SHA-256 of the CIPHERTEXT block) — live-proven.

## 8. Upload / download engines

See `docs/TRANSFERS.md` for the full wire protocol. Summary:

- **Upload:** intake (drop/panel) → `LocalTreeScan` (NFC relatives,
  topological order) → `ensureFolder` per directory (memoized) →
  `DriveClient.uploadFile` (draft → `POST /drive/blocks` → multipart to the
  storage host → commit). Blocks parallel per file deferred — per-job is
  sequential today. Whole files are buffered in memory (backlog B1).
  **Server gate:** `POST /drive/blocks` enforces an appversion allowlist —
  our honest header gets 2000; uploads stay disabled in this alpha (no
  spoofing — TRANSFERS.md §9).
- **Download:** `NSOpenPanel` destination → per file: unlock node →
  `openContentKey` → revision → blocks in a sliding-window TaskGroup
  (default 4) → SHA-256 verify per block BEFORE decrypt (fail-closed) →
  `reassemble` → atomic `*.nucleon-part` → rename → `uniqueDestination`
  (`nome (1).ext`). Folders recurse via `downloadTree`.

## 9. Concurrency

- All CPU/network work lives in actors (`SessionManager`, `KeyringCache`,
  `DriveClient`, `NodeKeyResolver`, `DriveListing`, `TransferQueue`,
  adapters). No `@MainActor` in `Core`.
- `LocalTreeScan` runs in `Task.detached`; UI observes `@Observable`
  view-models; no `Task` bodies in `View.body` except calls into objects
  that outlive the view.
- Cooperative cancellation per block; pause suspends job emission without
  aborting in-flight bytes.

## 10. Network rules (third-party compliance)

- Official endpoints only; base URL `https://mail.proton.me/api`; storage
  host taken from `BareURL` at runtime (never hardcoded).
- Honest header on EVERY call (API + storage):
  `x-pm-appversion: external-drive-nucleon_transfer@0.1.0-alpha`.
- No polling loops; event-based sync is on the backlog (B3) — until then
  listings refresh on demand and after local operations via
  `activity.remoteChanged(parentLinkIDs:)` → targeted `BrowserModel` reload.
- Retry: exponential backoff + jitter; `429`/`5xx`/`URLError` transient,
  everything else permanent; HV 9001 pauses the queue and surfaces to UI.
- Errors reaching the UI always pass through `UserFacingError` — actionable
  one-liners, no raw dumps.

## 11. Testability

- Root `Package.swift` compiles `Core/` as module `NucleonTransfer` +
  `NucleonTransferTests` — `swift test` runs the full suite without Xcode
  (171 tests: crypto vectors, queue, download, models, resolver, UI helpers).
- Protocols for mocks: `TransferUploader`, `RemoteFolderCreator`, sleeper
  injection for backoff tests, `Data(contentsOf:)` seams via adapters.
- No test touches the network; live verification runs via separate probes
  with credentials in env only (see `docs/DEVLOG.md`).
