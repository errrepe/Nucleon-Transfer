// Nucleon Transfer — "Keep me signed in" storage (F8.5-V1/V3).
// One Keychain item (KeychainStore, data-protection keychain, this device
// only, never synced) holds a versioned JSON blob: the refresh token, its
// UID, the salted key password (restored sessions have no password scope
// for /core/v4/keys/salts, so the unlock needs it) and the username.
// NEVER stored: the password, SRP values, the access token, unlocked keys.
// Reads fail soft (anything unreadable is "absent" and gets deleted);
// writes throw; deletes never throw (sign-out must always proceed).
// Temporary JSON buffers are zeroed best-effort (SecureBytes); decoded
// Strings cannot be wiped.
// "Require Touch ID" (V3): a random 256-bit KEK lives in a SECOND item
// protected by SecAccessControl(.biometryCurrentSet); the blob item then
// holds `SessionSeal` output (magic + AES-GCM) instead of plain JSON.
// Only `unlock(reason:)` reads the KEK (Touch ID prompt); the KEK then
// stays in this actor for the session, so token rotations re-seal
// silently. `lock()`/`delete()` drop it.
import CryptoKit
import Foundation

/// The persisted blob (schema v1). `description` is redacted so a stray
/// print or interpolation never leaks the secrets.
struct RememberedSession: Codable, Sendable, Equatable,
    CustomStringConvertible, CustomDebugStringConvertible
{
    static let currentVersion = 1

    var version: Int
    var uid: String
    var refreshToken: String
    /// bcrypt-derived key password (password-equivalent for the keys) —
    /// the same bytes `KeyringCache.unlockUserKeys(saltedPass:)` consumes.
    /// JSON-encoded as base64.
    var saltedKeyPass: Data
    var username: String
    var savedAt: Date

    init(uid: String, refreshToken: String, saltedKeyPass: Data,
         username: String, savedAt: Date = Date())
    {
        version = Self.currentVersion
        self.uid = uid
        self.refreshToken = refreshToken
        self.saltedKeyPass = saltedKeyPass
        self.username = username
        self.savedAt = savedAt
    }

    enum CodingKeys: String, CodingKey {
        case version, uid, refreshToken, saltedKeyPass, username, savedAt
    }

    /// Zeroes the salted key password in place (best-effort, see SecureBytes).
    mutating func wipe() {
        SecureBytes.wipe(&saltedKeyPass)
    }

    var description: String { "RememberedSession(v\(version), [redacted])" }
    var debugDescription: String { description }
}

actor SessionVault {
    /// Keychain account name of the remembered-session item.
    static let account = "remembered-session.v1"
    /// Keychain account name of the Touch ID protected KEK item (V3).
    static let kekAccount = "remembered-session.kek.v1"

    /// Outcome of the launch-time read (may show Touch ID).
    enum Unlock: Sendable, Equatable {
        /// Nothing remembered (or an unreadable/foreign item, now deleted).
        case absent
        case session(RememberedSession)
        /// Touch ID didn't release the KEK. `.invalidated` already deleted
        /// both items; `.cancelled`/`.unavailable` kept them.
        case failed(BiometricUnlockFailure)
    }

    private let store: any KeychainStore
    private let account: String
    private let kekAccount: String
    /// The unsealed KEK, held for the session after a Touch ID unlock or a
    /// sealed save. CryptoKit zeroes SymmetricKey storage when released.
    private var kek: SymmetricKey?

    init(store: any KeychainStore, account: String = SessionVault.account,
         kekAccount: String = SessionVault.kekAccount)
    {
        self.store = store
        self.account = account
        self.kekAccount = kekAccount
    }

    /// The remembered session, or nil when absent — never shows Touch ID.
    /// A sealed blob opens only with the KEK already in memory (otherwise
    /// nil, item kept). An unreadable item (store error) is absent;
    /// undecodable bytes, another schema version or a sealed blob the
    /// cached KEK can't open are deleted.
    func load() -> RememberedSession? {
        guard var raw = try? store.data(for: account) else { return nil }
        defer { SecureBytes.wipe(&raw) }
        switch SessionBlobFormat.detect(raw) {
        case .plain:
            return decodeOrDelete(raw)
        case .sealed:
            guard let kek else { return nil }
            guard var plain = try? SessionSeal.open(raw, key: kek) else {
                delete()
                return nil
            }
            defer { SecureBytes.wipe(&plain) }
            return decodeOrDelete(plain)
        case .unknown:
            delete()
            return nil
        }
    }

    /// Launch / "Use Touch ID": like `load`, but a sealed blob without a
    /// cached KEK reads the KEK item — the Touch ID prompt, with `reason`.
    /// KEK gone (fingerprints changed) or a blob it can't open → both
    /// items deleted, `.failed(.invalidated)`. Cancel / not available now
    /// → both kept.
    func unlock(reason: String) -> Unlock {
        guard var raw = try? store.data(for: account) else { return .absent }
        defer { SecureBytes.wipe(&raw) }
        switch SessionBlobFormat.detect(raw) {
        case .plain:
            return decodeOrDelete(raw).map(Unlock.session) ?? .absent
        case .unknown:
            delete()
            return .absent
        case .sealed:
            break
        }
        if kek == nil {
            switch readKEK(reason: reason) {
            case let .success(key):
                kek = key
            case let .failure(failure):
                if failure == .invalidated { delete() }
                return .failed(failure)
            }
        }
        guard let kek, var plain = try? SessionSeal.open(raw, key: kek) else {
            delete()
            return .failed(.invalidated)
        }
        defer { SecureBytes.wipe(&plain) }
        guard let session = decodeOrDelete(plain) else { return .failed(.invalidated) }
        return .session(session)
    }

    /// True when the blob item exists (it may still fail to decode/unseal).
    /// Never shows Touch ID.
    func hasRememberedSession() -> Bool {
        (try? store.data(for: account)) != nil
    }

    /// Format of the stored blob, nil when absent. Never shows Touch ID.
    func storedFormat() -> SessionBlobFormat? {
        guard var raw = try? store.data(for: account) else { return nil }
        defer { SecureBytes.wipe(&raw) }
        return SessionBlobFormat.detect(raw)
    }

    /// Stores `session`, replacing any existing item. `sealed`: under the
    /// KEK — the cached one, or a fresh random key written first to the
    /// Touch ID item (writing never prompts). Plain: the KEK item and the
    /// cached key are dropped. Throws the store's error
    /// (KeychainStoreError — a status code only).
    func save(_ session: RememberedSession, sealed: Bool = false) throws {
        var raw = try Self.encoder.encode(session)
        defer { SecureBytes.wipe(&raw) }
        guard sealed else {
            try store.set(raw, for: account, protection: .standard)
            dropKEK()
            return
        }
        let key: SymmetricKey
        if let kek {
            key = kek
        } else {
            key = SymmetricKey(size: .bits256)
            var bytes = key.withUnsafeBytes { Data($0) }
            defer { SecureBytes.wipe(&bytes) }
            try store.set(bytes, for: kekAccount, protection: .biometryCurrentSet)
            kek = key
        }
        var blob = try SessionSeal.seal(raw, key: key)
        defer { SecureBytes.wipe(&blob) }
        try store.set(blob, for: account, protection: .standard)
    }

    /// Rotated tokens (every refresh): rewrites uid + refresh token, keeps
    /// the salted key password and the sealing mode (re-sealed with the
    /// cached KEK — no Touch ID). No-op when nothing is remembered or a
    /// sealed blob can't be opened without a prompt — a refresh never
    /// creates an item. Returns whether an item was updated.
    @discardableResult
    func updateTokens(uid: String, refreshToken: String) throws -> Bool {
        guard var current = load() else { return false }
        defer { current.wipe() }
        guard current.uid != uid || current.refreshToken != refreshToken else { return true }
        current.uid = uid
        current.refreshToken = refreshToken
        try save(current, sealed: kek != nil)
        return true
    }

    /// "Require Touch ID" switched (V3): re-seal a plain blob under a new
    /// KEK, or unseal a sealed one back to plain (cached KEK, else a Touch
    /// ID prompt with `reason`). Nothing remembered → only the KEK state
    /// follows. Returns false when the change couldn't be applied (the
    /// caller reverts the toggle); the stored session is left as it was.
    func setSealed(_ sealed: Bool, reason: String) -> Bool {
        guard let format = storedFormat() else {
            if !sealed { dropKEK() }
            return true
        }
        switch (format, sealed) {
        case (.plain, false):
            dropKEK()
            return true
        case (.sealed, true):
            return true
        case (.plain, true):
            guard var session = load() else { return true }
            defer { session.wipe() }
            do {
                try save(session, sealed: true)
                return true
            } catch {
                // The blob item still holds the plain session (the KEK
                // write or the sealed write failed): drop the orphan KEK.
                dropKEK()
                return false
            }
        case (.sealed, false):
            switch unlock(reason: reason) {
            case var .session(session):
                defer { session.wipe() }
                return (try? save(session, sealed: false)) != nil
            case .absent, .failed(.invalidated):
                dropKEK()
                return true
            case .failed:
                return false
            }
        case (.unknown, _):
            delete()
            return true
        }
    }

    /// Forgets the cached KEK (the session ended but the items stay — a
    /// network-failed restore). The next `unlock` prompts again.
    func lock() {
        kek = nil
    }

    /// Removes both items and the cached KEK. Never throws: callers are
    /// signing out or recovering, and a store failure must not block that.
    func delete() {
        try? store.delete(account: account)
        dropKEK()
    }

    // MARK: - internals

    private func dropKEK() {
        kek = nil
        try? store.delete(account: kekAccount)
    }

    /// The KEK via Touch ID. A missing item or a wrong-size value is
    /// `.invalidated`; an unclassified Keychain error is `.unavailable`
    /// (kept — the password login replaces both items anyway).
    private func readKEK(reason: String) -> Result<SymmetricKey, BiometricUnlockFailure> {
        do {
            guard var bytes = try store.authenticatedData(for: kekAccount, reason: reason) else {
                return .failure(.invalidated)
            }
            defer { SecureBytes.wipe(&bytes) }
            guard bytes.count == SessionSeal.keyByteCount else { return .failure(.invalidated) }
            return .success(SymmetricKey(data: bytes))
        } catch let error as KeychainStoreError {
            return .failure(error.biometricFailure ?? .unavailable)
        } catch {
            return .failure(.unavailable)
        }
    }

    /// Decodes a plain v1 blob; anything else deletes both items.
    private func decodeOrDelete(_ raw: Data) -> RememberedSession? {
        guard let probe = try? JSONDecoder().decode(VersionProbe.self, from: raw),
              probe.version == RememberedSession.currentVersion,
              let session = try? Self.decoder.decode(RememberedSession.self, from: raw)
        else {
            delete()
            return nil
        }
        return session
    }

    private struct VersionProbe: Decodable {
        var version: Int
    }

    private static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.dataEncodingStrategy = .base64
        return e
    }

    private static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        d.dataDecodingStrategy = .base64
        return d
    }
}

/// On-disk shape of the remembered-session item (V3 format marker).
enum SessionBlobFormat: Sendable, Equatable {
    /// RememberedSession JSON (starts with "{").
    case plain
    /// `SessionSeal` output: `sealedMagic` + AES-GCM nonce‖ciphertext‖tag.
    case sealed
    /// Neither — foreign or corrupt; deleted on read.
    case unknown

    /// "NTSEAL" + format version 1. Never a valid JSON prefix.
    static let sealedMagic = Data("NTSEAL\u{01}".utf8)

    static func detect(_ blob: Data) -> SessionBlobFormat {
        if blob.starts(with: sealedMagic) { return .sealed }
        if blob.first == UInt8(ascii: "{") { return .plain }
        return .unknown
    }
}

/// AES-256-GCM sealing of the blob under the Touch ID KEK (V3). The magic
/// is also the associated data, so a blob can't be re-labelled.
enum SessionSeal {
    static let keyByteCount = 32

    enum SealError: Error, Sendable { case notSealed, noCombinedForm }

    static func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: SessionBlobFormat.sealedMagic)
        guard let combined = box.combined else { throw SealError.noCombinedForm }
        return SessionBlobFormat.sealedMagic + combined
    }

    /// Throws on a wrong key, any tampered byte, or a non-sealed blob.
    static func open(_ blob: Data, key: SymmetricKey) throws -> Data {
        guard SessionBlobFormat.detect(blob) == .sealed else { throw SealError.notSealed }
        let box = try AES.GCM.SealedBox(combined: blob.dropFirst(SessionBlobFormat.sealedMagic.count))
        return try AES.GCM.open(box, using: key, authenticating: SessionBlobFormat.sealedMagic)
    }
}

/// Settings › "Forget This Mac" (V3): both Keychain items and the
/// remembered username go; the live session (if any) is untouched.
enum SavedSignIn {
    static func forgetThisMac(vault: SessionVault, defaults: UserDefaults) async {
        await vault.delete()
        AppSettings.clearLastUsername(in: defaults)
    }
}
