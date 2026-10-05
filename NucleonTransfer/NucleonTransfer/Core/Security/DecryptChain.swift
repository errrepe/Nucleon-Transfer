// Nucleon Transfer — key hierarchy unlock orchestration (F3b chain).
// Mirrors go-proton-api Share.GetKeyRing + Link.GetKeyRing/GetName and the
// rclone bridge flow: share via address keys, node via parent keyring,
// names via node keyring. Pure crypto: callers supply fetched models.
// EC only (algo 18/22); RSA keys throw unsupportedAlgo (follow-up).
// F8.1-S2: key-level signatures (share/node passphrase, address-key Token,
// NodeHashKey) are MANDATORY — missing, invalid, weak-hash or unverifiable
// signatures throw a specific DecryptChainError (fail closed). Names only
// report an outcome (content-level → DriveItem.signatureIssue).
import CryptoKit
import Foundation

enum DecryptChainError: Error, Sendable, Equatable {
    case missingMaterial(String)
    /// Key-level material arrived without its signature.
    case signatureMissing(what: String)
    /// Signature present but no allowed signer verifies it.
    case signatureInvalid(what: String)
    /// Signature made with a collision-broken hash (MD5/SHA-1, F8.1-S3).
    case weakSignatureHash(what: String, algo: UInt8)
    /// The claimed signer is not one of the user's addresses — its public
    /// keys are not available, so the material cannot be trusted.
    case unknownSigner(what: String)
}

enum DecryptChain {
    /// Turns a signature outcome into a fail-closed check for key-level
    /// material: anything but `.valid` throws.
    static func require(_ outcome: SignatureVerification.Outcome, _ what: String) throws {
        switch outcome {
        case .valid: return
        case .missing: throw DecryptChainError.signatureMissing(what: what)
        case .invalid: throw DecryptChainError.signatureInvalid(what: what)
        case let .weakHash(algo): throw DecryptChainError.weakSignatureHash(what: what, algo: algo)
        case .noVerifier: throw DecryptChainError.unknownSigner(what: what)
        }
    }

    /// Unlocks a share's private key blob (all secret packets: primary +
    /// subkeys): decrypts Passphrase with address ECDH candidates, then
    /// REQUIRES the detached PassphraseSignature to verify with an address
    /// Ed25519 point.
    /// Source: go-proton-api share_types.go `Share.GetKeyRing` (decrypt with
    /// addrKR, `addrKR.VerifyDetached` — a missing signature fails
    /// `NewPGPSignatureFromArmored`); C# SDK Api/Shares/ShareDto.cs marks
    /// `PassphraseSignature` as `required`.
    static func unlockShare(
        _ share: DriveShare,
        addressKeys: [KeyringCache.UnlockedKey]
    ) throws -> [KeyringCache.UnlockedKey] {
        guard let passArmored = share.passphrase, !passArmored.isEmpty,
              let keyArmored = share.key, !keyArmored.isEmpty else {
            throw DecryptChainError.missingMaterial("share passphrase/key")
        }
        let candidates = addressKeys.compactMap(\.candidate)
        var passphrase = try MessageDecrypt.decrypt(armored: passArmored, candidates: candidates)
        defer { SecureBytes.wipe(&passphrase) }
        try require(SignatureVerification.detached(
            armored: share.passphraseSignature, over: [passphrase],
            signerPoints: edPoints(addressKeys)
        ), "share passphrase")
        return try unlockSecretKeys(armored: keyArmored, passphrase: passphrase,
                                    idPrefix: "share/\(share.shareID)")
    }

    /// Unlocks a link's node key blob with parent candidates (share keys for
    /// the root, folder node keys below). The NodePassphraseSignature is
    /// REQUIRED and must verify with `signerPoints` (see
    /// `nodeSignerPoints`). Source: go-proton-api link_types.go
    /// `Link.GetKeyRing` (`addrKR.VerifyDetached`, missing signature is an
    /// error).
    static func unlockNode(
        _ link: DriveLink,
        parentCandidates: [DecryptCandidate],
        signerPoints: [Data]
    ) throws -> [KeyringCache.UnlockedKey] {
        guard let passArmored = link.nodePassphrase, !passArmored.isEmpty,
              let keyArmored = link.nodeKey, !keyArmored.isEmpty else {
            throw DecryptChainError.missingMaterial("node passphrase/key")
        }
        var passphrase = try MessageDecrypt.decrypt(armored: passArmored, candidates: parentCandidates)
        defer { SecureBytes.wipe(&passphrase) }
        try require(SignatureVerification.detached(
            armored: link.nodePassphraseSignature, over: [passphrase],
            signerPoints: signerPoints
        ), "node passphrase")
        return try unlockSecretKeys(armored: keyArmored, passphrase: passphrase,
                                    idPrefix: "node/\(link.linkID)")
    }

    /// Allowed signers of a node passphrase: the address keys of the
    /// link's SignatureEmail, or — when the email is empty (anonymous
    /// upload) — the PARENT key. Source: C# SDK Nodes/Cryptography/
    /// NodeCrypto.cs `DecryptLinkAsync` → `DecryptPassphrase(...,
    /// authorshipClaim.GetKeyRing(parentKey))`.
    static func nodeSignerPoints(
        _ link: DriveLink,
        parentKeys: [KeyringCache.UnlockedKey],
        addressKeys: [KeyringCache.UnlockedKey]
    ) -> [Data] {
        SignatureVerification.signerPoints(
            claimedEmail: link.signatureEmail, addressKeys: addressKeys,
            anonymousFallback: edPoints(parentKeys)
        )
    }

    /// Decrypts a link's filename with its PARENT's candidates (names are
    /// encrypted to the parent keyring: the root's name to the share key,
    /// a child's name to the parent node key — verified live: root Name
    /// PKESK keyID == share #18 fingerprint tail, child Name PKESK keyID ==
    /// parent #18 tail). Signature NOT checked — use `decryptNameVerified`
    /// where the outcome can be surfaced.
    static func decryptName(
        _ link: DriveLink,
        parentCandidates: [DecryptCandidate]
    ) throws -> String {
        let bytes = try MessageDecrypt.decrypt(armored: link.name, candidates: parentCandidates)
        guard let name = String(data: bytes, encoding: .utf8) else {
            throw DecryptChainError.missingMaterial("name encoding")
        }
        return name
    }

    /// Decrypts a link's name AND checks its inline (one-pass) signature.
    /// Content-level: the outcome is returned, never thrown, so browsing
    /// continues with a warning badge (DriveItem.signatureIssue).
    /// Signers: the NameSignatureEmail's address keys, or the parent key
    /// when that email is empty — C# SDK NodeCrypto.cs `DecryptLinkAsync`
    /// (`nameAuthorshipClaim`) + `DecryptName(..., GetKeyRing(parentKey))`.
    /// Links without a NameSignatureEmail field (go-proton-api link_types.go
    /// does not model it; `Link.GetName(parentNodeKR, addrKR)` verifies with
    /// the address keyring) also accept the SignatureEmail's address keys.
    static func decryptNameVerified(
        _ link: DriveLink,
        parentKeys: [KeyringCache.UnlockedKey],
        addressKeys: [KeyringCache.UnlockedKey]
    ) throws -> (name: String, signature: SignatureVerification.Outcome) {
        let parentPoints = edPoints(parentKeys)
        let signers: [Data]
        if let nameEmail = link.nameSignatureEmail, !nameEmail.isEmpty {
            signers = SignatureVerification.signerPoints(
                claimedEmail: nameEmail, addressKeys: addressKeys, anonymousFallback: parentPoints
            )
        } else if let email = link.signatureEmail, !email.isEmpty {
            signers = parentPoints + SignatureVerification.signerPoints(
                claimedEmail: email, addressKeys: addressKeys, anonymousFallback: []
            )
        } else {
            signers = parentPoints
        }
        let (bytes, outcome) = try SignatureVerification.decryptInline(
            armored: link.name, candidates: parentKeys.compactMap(\.candidate),
            signerPoints: signers
        )
        guard let name = String(data: bytes, encoding: .utf8) else {
            throw DecryptChainError.missingMaterial("name encoding")
        }
        return (name, outcome)
    }

    /// Decrypts a folder's NodeHashKey with its node keys and REQUIRES the
    /// inline signature (key-level). Signers: the node key plus the
    /// SignatureEmail's address keys — C# SDK NodeCrypto.cs
    /// `DecryptHashKey` / `GetContentKeyAndHashKeyVerificationKeyRing`
    /// (go-proton-api link_types.go `GetHashKey` verifies with nodeKR).
    /// Returns the decoded 32-byte name-HMAC key (base64-utf8 of 32 random
    /// bytes on the wire — F4.2 live-verified).
    static func unlockHashKey(
        _ link: DriveLink,
        nodeKeys: [KeyringCache.UnlockedKey],
        addressKeys: [KeyringCache.UnlockedKey]
    ) throws -> Data {
        guard let armored = link.folderProperties?.nodeHashKey, !armored.isEmpty else {
            throw TransferFailure.permanent("folder has no NodeHashKey")
        }
        let signers = edPoints(nodeKeys) + SignatureVerification.signerPoints(
            claimedEmail: link.signatureEmail, addressKeys: addressKeys, anonymousFallback: []
        )
        let (plain, outcome) = try SignatureVerification.decryptInline(
            armored: armored, candidates: nodeKeys.compactMap(\.candidate), signerPoints: signers
        )
        try require(outcome, "folder hash key")
        guard let token = String(data: plain, encoding: .utf8),
              let seed = Data(base64Encoded: token),
              seed.count == 32
        else {
            throw TransferFailure.permanent("malformed NodeHashKey")
        }
        return seed
    }

    /// Decrypts an address key's Token with the user keys and REQUIRES its
    /// detached Signature to verify with a user Ed25519 key.
    /// Source: go-proton-api keyring.go `Key.getPassphraseFromToken`
    /// (`kr.Decrypt` then `kr.VerifyDetached(token, sig)` with the user
    /// keyring). A Token without Signature is rejected (fail closed).
    static func addressKeyPassphrase(
        token: String,
        signature: String?,
        userKeys: [KeyringCache.UnlockedKey]
    ) throws -> Data {
        let passphrase = try MessageDecrypt.decrypt(
            armored: token, candidates: userKeys.compactMap(\.candidate)
        )
        try require(SignatureVerification.detached(
            armored: signature, over: [Data(passphrase)], signerPoints: edPoints(userKeys)
        ), "address key token")
        return Data(passphrase)
    }

    /// Ed25519 points (algo 22) of unlocked keys — signer candidates.
    static func edPoints(_ keys: [KeyringCache.UnlockedKey]) -> [Data] {
        keys.filter { $0.algo == 22 }.compactMap { k in
            try? Curve25519.Signing.PrivateKey(rawRepresentation: k.seed).publicKey.rawRepresentation
        }
    }

    // MARK: - key packets

    /// Parses + decrypts every secret packet in an armored key, verifying each
    /// seed against its public point. Shared by KeyringCache and the chain.
    static func unlockSecretKeys(armored: String, passphrase: Data, idPrefix: String) throws -> [KeyringCache.UnlockedKey] {
        let raw = try Armor.decode(armored)
        var out: [KeyringCache.UnlockedKey] = []
        for packet in try PGPPackets.parse(raw) where packet.tag == 5 || packet.tag == 7 {
            out.append(try unlockSecretPacket(packet, passphrase: passphrase, idPrefix: idPrefix))
        }
        guard !out.isEmpty else { throw DecryptChainError.missingMaterial("secret packet") }
        return out
    }

    static func unlockSecretPacket(_ packet: PGPPacket, passphrase: Data, idPrefix: String) throws -> KeyringCache.UnlockedKey {
        let sk = try SecretKeyPacket.parse(body: packet.body)
        guard sk.publicAlgo == 18 || sk.publicAlgo == 22 else {
            throw SecretKeyError.unsupportedAlgo(sk.publicAlgo)
        }
        var plain = try SecretKeyUnlock.decrypt(sk, passphrase: passphrase)
        defer { SecureBytes.wipe(&plain) }   // secret MPIs + checksum (F8.1-S7)
        let seed = sk.publicAlgo == 18
            ? try SecretKeyUnlock.ecdhScalar(plaintext: plain)
            : try SecretKeyUnlock.secretScalar(plaintext: plain)
        let point = sk.publicPoint ?? Data()
        let ok = sk.publicAlgo == 22
            ? SecretKeyVerify.ed25519PublicMatches(seed: seed, pointMPI: point)
            : SecretKeyVerify.x25519PublicMatches(scalar: seed, pointMPI: point)
        guard ok else { throw ProtonAPIError.keyVerificationFailed }
        return KeyringCache.UnlockedKey(
            keyID: "\(idPrefix)#\(sk.publicAlgo)", algo: sk.publicAlgo, seed: seed,
            fingerprint: try PGPFingerprint.v4(publicBody: sk.publicBody),
            kdfHash: sk.kdfHash ?? 8, kdfCipher: sk.kdfCipher ?? 9,
            curveOIDBody: sk.curveOID ?? Data()
        )
    }
}
