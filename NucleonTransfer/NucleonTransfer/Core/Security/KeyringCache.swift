// Nucleon Transfer — in-memory unlocked key seeds (F3b-1: user keys).
// Seeds live ONLY in this actor's memory: never Keychain, never disk, never logs.
// Salted pass comes from SessionManager.fetchSaltedKeyPass (password scope).
import Foundation

actor KeyringCache {
    struct UnlockedKey: Sendable {
        var keyID: String
        var algo: UInt8
        var seed: Data
        /// v4 fingerprint of the secret packet's public part (KDF recipient ID).
        var fingerprint: Data
        var kdfHash: UInt8
        var kdfCipher: UInt8
        var curveOIDBody: Data
        /// Email of the address owning this key (address keys only; set by
        /// `unlockAddressKeys`). Selects signers for a claimed
        /// SignatureEmail (SignatureVerification.signerPoints, F8.1-S2).
        var email: String? = nil

        var candidate: DecryptCandidate? {
            guard algo == 18, fingerprint.count == 20 else { return nil }
            return DecryptCandidate(scalarLE: seed, fingerprint: fingerprint,
                                    kdfHash: kdfHash, kdfCipher: kdfCipher,
                                    curveOIDBody: curveOIDBody)
        }
    }

    private let api: APIClient
    private let sessions: SessionManager
    private var seeds: [String: Data] = [:]

    init(api: APIClient = APIClient(), sessions: SessionManager) {
        self.api = api
        self.sessions = sessions
    }

    func fetchUser() async throws -> ProtonUser {
        try await sessions.withAuth { uid, token in
            try await self.api.get(ProtonUserResponse.self, path: "/core/v4/users", uid: uid, accessToken: token).user
        }
    }

    /// Address list (email fallback for the account header — S0.3).
    func fetchAddresses() async throws -> [ProtonAddress] {
        try await sessions.withAuth { uid, token in
            try await self.api.get(AddressesResponse.self, path: "/core/v4/addresses", uid: uid, accessToken: token).addresses
        }
    }

    /// Unlocks all active user secret keys with the salted pass, verifying each
    /// decrypted seed against its public point (constant-size compare only).
    @discardableResult
    func unlockUserKeys(saltedPass: Data) async throws -> [UnlockedKey] {
        let user = try await fetchUser()
        var out: [UnlockedKey] = []
        for ref in user.keys where ref.isActive {
            out.append(contentsOf: try unlockSecretKeys(armored: ref.privateKey, passphrase: saltedPass, idPrefix: ref.id))
        }
        guard !out.isEmpty else { throw ProtonAPIError.keyVerificationFailed }
        return out
    }

    /// Unlocks address keys: each address key's Token (passphrase encrypted to
    /// a user ECDH subkey) is decrypted with the user candidates, its
    /// detached Signature is verified against the user keys (fail-closed,
    /// F8.1-S2), then the address secret key is unlocked with that
    /// passphrase (F3b-2). Each unlocked key carries its address email.
    @discardableResult
    func unlockAddressKeys(userKeys: [UnlockedKey]) async throws -> [UnlockedKey] {
        let addresses = try await fetchAddresses()
        var out: [UnlockedKey] = []
        for addr in addresses {
            for ref in addr.keys where ref.isActive {
                guard let tokenArmored = ref.token, !tokenArmored.isEmpty else { continue }
                let passphrase = try DecryptChain.addressKeyPassphrase(
                    token: tokenArmored, signature: ref.signature, userKeys: userKeys
                )
                var keys = try unlockSecretKeys(armored: ref.privateKey, passphrase: passphrase, idPrefix: "\(addr.id)/\(ref.id)")
                for i in keys.indices { keys[i].email = addr.email }
                out.append(contentsOf: keys)
            }
        }
        guard !out.isEmpty else { throw ProtonAPIError.keyVerificationFailed }
        return out
    }

    /// Parses + decrypts every secret packet in an armored key (delegates to
    /// DecryptChain), recording seeds in memory.
    func unlockSecretKeys(armored: String, passphrase: Data, idPrefix: String) throws -> [UnlockedKey] {
        let out = try DecryptChain.unlockSecretKeys(armored: armored, passphrase: passphrase, idPrefix: idPrefix)
        for k in out { seeds[k.keyID] = k.seed }
        return out
    }

    func seed(for keyID: String) -> Data? { seeds[keyID] }

    func lock() { seeds.removeAll() }
}
