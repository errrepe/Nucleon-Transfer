// Nucleon Transfer — "Keep me signed in" storage (F8.5-V1).
// One Keychain item (KeychainStore, data-protection keychain, this device
// only, never synced) holds a versioned JSON blob: the refresh token, its
// UID, the salted key password (restored sessions have no password scope
// for /core/v4/keys/salts, so the unlock needs it) and the username.
// NEVER stored: the password, SRP values, the access token, unlocked keys.
// Reads fail soft (anything unreadable is "absent" and gets deleted);
// writes throw; deletes never throw (sign-out must always proceed).
// Temporary JSON buffers are zeroed best-effort (SecureBytes); decoded
// Strings cannot be wiped.
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
    /// Keychain account name of the single remembered-session item.
    static let account = "remembered-session.v1"

    private let store: any KeychainStore
    private let account: String

    init(store: any KeychainStore, account: String = SessionVault.account) {
        self.store = store
        self.account = account
    }

    /// The remembered session, or nil when absent. An unreadable item
    /// (store error), undecodable bytes or another schema version is
    /// treated as absent; undecodable / other-version items are deleted.
    func load() -> RememberedSession? {
        guard var raw = try? store.data(for: account) else { return nil }
        defer { SecureBytes.wipe(&raw) }
        guard let probe = try? JSONDecoder().decode(VersionProbe.self, from: raw),
              probe.version == RememberedSession.currentVersion,
              let session = try? Self.decoder.decode(RememberedSession.self, from: raw)
        else {
            delete()
            return nil
        }
        return session
    }

    /// True when an item exists (it may still fail to decode on `load`).
    func hasRememberedSession() -> Bool {
        (try? store.data(for: account)) != nil
    }

    /// Stores `session`, replacing any existing item. Throws the store's
    /// error (KeychainStoreError — a status code only).
    func save(_ session: RememberedSession) throws {
        var raw = try Self.encoder.encode(session)
        defer { SecureBytes.wipe(&raw) }
        try store.set(raw, for: account, protection: .standard)
    }

    /// Rotated tokens (every refresh): rewrites uid + refresh token, keeps
    /// the salted key password. No-op when nothing is remembered — a
    /// refresh never creates an item. Returns whether an item was updated.
    @discardableResult
    func updateTokens(uid: String, refreshToken: String) throws -> Bool {
        guard var current = load() else { return false }
        defer { current.wipe() }
        guard current.uid != uid || current.refreshToken != refreshToken else { return true }
        current.uid = uid
        current.refreshToken = refreshToken
        try save(current)
        return true
    }

    /// Removes the item. Never throws: callers are signing out or
    /// recovering, and a store failure must not block that.
    func delete() {
        try? store.delete(account: account)
    }

    // MARK: - coding

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
