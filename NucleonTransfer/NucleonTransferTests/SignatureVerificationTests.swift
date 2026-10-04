// Nucleon Transfer — F8.1-S2 fail-closed signature suite (Swift Testing).
// Key-level material (share/node passphrase, address-key Token,
// NodeHashKey) throws on missing/invalid/weak/unknown signatures;
// content-level checks (names, content key, manifest, blocks) report or
// fail downloads. Offline; throwaway keys built with NodeKeyGen /
// DetachedSign / MessageEncrypt.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - fixtures

/// A throwaway signing (#22) + encryption (#18) key pair, as unlocked keys.
private struct TestIdentity {
    let ed = Curve25519.Signing.PrivateKey()
    let x = Curve25519.KeyAgreement.PrivateKey()
    let edFP = Data((0..<20).map { _ in UInt8.random(in: .min ... .max) })
    let xFP = Data((0..<20).map { _ in UInt8.random(in: .min ... .max) })
    var email: String? = nil

    var keys: [KeyringCache.UnlockedKey] {
        [
            KeyringCache.UnlockedKey(
                keyID: "ed", algo: 22, seed: ed.rawRepresentation, fingerprint: edFP,
                kdfHash: 8, kdfCipher: 9, curveOIDBody: NodeKeyGen.edOID, email: email
            ),
            KeyringCache.UnlockedKey(
                keyID: "x", algo: 18, seed: x.rawRepresentation, fingerprint: xFP,
                kdfHash: 8, kdfCipher: 7, curveOIDBody: NodeKeyGen.ecdhOID, email: email
            ),
        ]
    }

    var recipient: EncryptRecipient {
        EncryptRecipient(
            publicPoint: x.publicKey.rawRepresentation, fingerprint: xFP,
            curveOIDBody: NodeKeyGen.ecdhOID, kdfHash: 8, kdfCipher: 7
        )
    }

    var point: Data { ed.publicKey.rawRepresentation }

    func sign(_ data: Data, hashAlgo: UInt8 = 8) throws -> String {
        try DetachedSign.sign(
            data: data, signerSeedLE: ed.rawRepresentation,
            signerKeyID: Data(edFP.suffix(8)), signerFingerprint: edFP,
            hashAlgo: hashAlgo, salt: DetachedSign.freshSalt(16)
        )
    }

    func encryptSigned(_ data: Data, to recipient: EncryptRecipient) throws -> String {
        try MessageEncrypt.encryptSigned(
            plaintext: data, recipient: recipient,
            signerSeedLE: ed.rawRepresentation, signerKeyID: Data(edFP.suffix(8)),
            signerFingerprint: edFP, hashAlgo: 8, salt: DetachedSign.freshSalt(16)
        )
    }
}

/// A fresh node key locked with a fresh passphrase.
private struct TestNode {
    let passphrase = NodeKeyGen.randomPassphrase()
    let generated: NodeKeyGen.GeneratedKey

    init() throws {
        generated = try NodeKeyGen.generate(passphrase: passphrase)
    }
}

private func makeShare(
    passphrase: String, key: String, signature: String?
) -> DriveShare {
    DriveShare(
        shareID: "S", linkID: "R", volumeID: nil, type: 1, state: 1,
        creator: "me@proton.me", addressID: "addr", addressKeyID: nil,
        key: key, passphrase: passphrase, passphraseSignature: signature
    )
}

private func makeLink(
    name: String = "enc", nodeKey: String? = nil, passphrase: String? = nil,
    signature: String? = nil, email: String? = nil, nameEmail: String? = nil,
    hashKey: String? = nil
) -> DriveLink {
    DriveLink(
        linkID: "L", parentLinkID: "P", type: 1, name: name, hash: nil,
        size: 0, state: 1, mimeType: nil, createTime: 0, modifyTime: 0,
        expirationTime: nil, nodeKey: nodeKey, nodePassphrase: passphrase,
        nodePassphraseSignature: signature, signatureEmail: email,
        nameSignatureEmail: nameEmail, xAttr: nil, fileProperties: nil,
        folderProperties: hashKey.map { FolderProperties(nodeHashKey: $0) }
    )
}

// MARK: - key-level: share + node passphrase

struct PassphraseSignatureTests {
    private func shareFixture(
        signedBy signer: TestIdentity?, hashAlgo: UInt8 = 8
    ) throws -> (DriveShare, TestIdentity) {
        let address = TestIdentity()
        let node = try TestNode()
        let enc = try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: address.recipient)
        let sig = try signer.map { try $0.sign(node.passphrase, hashAlgo: hashAlgo) }
        return (makeShare(passphrase: enc, key: node.generated.armoredKey, signature: sig), address)
    }

    @Test func shareWithValidSignatureUnlocks() throws {
        let address = TestIdentity()
        let node = try TestNode()
        let enc = try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: address.recipient)
        let share = makeShare(
            passphrase: enc, key: node.generated.armoredKey,
            signature: try address.sign(node.passphrase)
        )
        let keys = try DecryptChain.unlockShare(share, addressKeys: address.keys)
        #expect(keys.count == 2)
    }

    @Test func shareWithoutSignatureThrows() throws {
        let (share, address) = try shareFixture(signedBy: nil)
        #expect(throws: DecryptChainError.signatureMissing(what: "share passphrase")) {
            _ = try DecryptChain.unlockShare(share, addressKeys: address.keys)
        }
    }

    @Test func shareWithEmptySignatureThrows() throws {
        let (share0, address) = try shareFixture(signedBy: nil)
        var share = share0
        share.passphraseSignature = ""
        #expect(throws: DecryptChainError.signatureMissing(what: "share passphrase")) {
            _ = try DecryptChain.unlockShare(share, addressKeys: address.keys)
        }
    }

    @Test func shareSignedByAnotherKeyThrows() throws {
        let (share, address) = try shareFixture(signedBy: TestIdentity())
        #expect(throws: DecryptChainError.signatureInvalid(what: "share passphrase")) {
            _ = try DecryptChain.unlockShare(share, addressKeys: address.keys)
        }
    }

    @Test func weakHashSurfacesAsItsOwnError() throws {
        // SHA-1 signature by the RIGHT key: must not degrade to "invalid"
        // or nil — the weak hash is reported explicitly.
        let address = TestIdentity()
        let node = try TestNode()
        let enc = try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: address.recipient)
        let share = makeShare(
            passphrase: enc, key: node.generated.armoredKey,
            signature: try address.sign(node.passphrase, hashAlgo: 2)
        )
        #expect(throws: DecryptChainError.weakSignatureHash(what: "share passphrase", algo: 2)) {
            _ = try DecryptChain.unlockShare(share, addressKeys: address.keys)
        }
    }

    @Test func nodeWithoutSignatureThrows() throws {
        let parent = TestIdentity()
        let address = TestIdentity()
        let node = try TestNode()
        let link = makeLink(
            nodeKey: node.generated.armoredKey,
            passphrase: try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: parent.recipient)
        )
        #expect(throws: DecryptChainError.signatureMissing(what: "node passphrase")) {
            _ = try DecryptChain.unlockNode(
                link, parentCandidates: parent.keys.compactMap(\.candidate),
                signerPoints: [address.point]
            )
        }
    }

    @Test func nodeWithInvalidSignatureThrows() throws {
        let parent = TestIdentity()
        let address = TestIdentity()
        let node = try TestNode()
        let link = makeLink(
            nodeKey: node.generated.armoredKey,
            passphrase: try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: parent.recipient),
            signature: try address.sign(Data("other passphrase".utf8))
        )
        #expect(throws: DecryptChainError.signatureInvalid(what: "node passphrase")) {
            _ = try DecryptChain.unlockNode(
                link, parentCandidates: parent.keys.compactMap(\.candidate),
                signerPoints: [address.point]
            )
        }
    }

    @Test func nodeSignerFollowsSignatureEmail() throws {
        var parent = TestIdentity()
        parent.email = nil
        var mine = TestIdentity()
        mine.email = "Me@Proton.me"
        let node = try TestNode()
        let enc = try MessageEncrypt.encrypt(plaintext: node.passphrase, recipient: parent.recipient)

        // Signed by my address, claimed email matches (case-insensitive).
        let ok = makeLink(
            nodeKey: node.generated.armoredKey, passphrase: enc,
            signature: try mine.sign(node.passphrase), email: "me@proton.me"
        )
        let points = DecryptChain.nodeSignerPoints(ok, parentKeys: parent.keys, addressKeys: mine.keys)
        #expect(points == [mine.point])
        #expect(try DecryptChain.unlockNode(
            ok, parentCandidates: parent.keys.compactMap(\.candidate), signerPoints: points
        ).count == 2)

        // Anonymous link (no SignatureEmail): only the PARENT key may sign.
        let anon = makeLink(
            nodeKey: node.generated.armoredKey, passphrase: enc,
            signature: try parent.sign(node.passphrase)
        )
        let anonPoints = DecryptChain.nodeSignerPoints(anon, parentKeys: parent.keys, addressKeys: mine.keys)
        #expect(anonPoints == [parent.point])
        #expect(try DecryptChain.unlockNode(
            anon, parentCandidates: parent.keys.compactMap(\.candidate), signerPoints: anonPoints
        ).count == 2)

        // Foreign signer email: no verifier available → fail closed.
        let foreign = makeLink(
            nodeKey: node.generated.armoredKey, passphrase: enc,
            signature: try mine.sign(node.passphrase), email: "someone@else.me"
        )
        let foreignPoints = DecryptChain.nodeSignerPoints(foreign, parentKeys: parent.keys, addressKeys: mine.keys)
        #expect(foreignPoints.isEmpty)
        #expect(throws: DecryptChainError.unknownSigner(what: "node passphrase")) {
            _ = try DecryptChain.unlockNode(
                foreign, parentCandidates: parent.keys.compactMap(\.candidate),
                signerPoints: foreignPoints
            )
        }
    }
}

// MARK: - key-level: address-key Token + NodeHashKey

struct AddressTokenAndHashKeySignatureTests {
    @Test func addressTokenRequiresUserSignature() throws {
        let user = TestIdentity()
        let token = Data("address-key-passphrase".utf8)
        let enc = try MessageEncrypt.encrypt(plaintext: token, recipient: user.recipient)

        #expect(try DecryptChain.addressKeyPassphrase(
            token: enc, signature: try user.sign(token), userKeys: user.keys
        ) == token)
        #expect(throws: DecryptChainError.signatureInvalid(what: "address key token")) {
            _ = try DecryptChain.addressKeyPassphrase(
                token: enc, signature: try TestIdentity().sign(token), userKeys: user.keys
            )
        }
        #expect(throws: DecryptChainError.signatureInvalid(what: "address key token")) {
            _ = try DecryptChain.addressKeyPassphrase(
                token: enc, signature: try user.sign(Data("tampered".utf8)), userKeys: user.keys
            )
        }
        #expect(throws: DecryptChainError.signatureMissing(what: "address key token")) {
            _ = try DecryptChain.addressKeyPassphrase(token: enc, signature: nil, userKeys: user.keys)
        }
    }

    @Test func hashKeySignedByNodeUnlocks() throws {
        let node = TestIdentity()
        let seed = Data((0..<32).map { UInt8($0) })
        let armored = try node.encryptSigned(Data(seed.base64EncodedString().utf8), to: node.recipient)
        let link = makeLink(hashKey: armored)
        #expect(try DecryptChain.unlockHashKey(link, nodeKeys: node.keys, addressKeys: []) == seed)
        // Live NodeUnlocker wires the same check.
        #expect(try NodeUnlocker.live.folderHashKey(link, node.keys, []) == seed)
    }

    @Test func unsignedHashKeyThrows() throws {
        let node = TestIdentity()
        let seed = Data(repeating: 4, count: 32)
        let armored = try MessageEncrypt.encrypt(
            plaintext: Data(seed.base64EncodedString().utf8), recipient: node.recipient
        )
        #expect(throws: DecryptChainError.signatureMissing(what: "folder hash key")) {
            _ = try DecryptChain.unlockHashKey(makeLink(hashKey: armored), nodeKeys: node.keys, addressKeys: [])
        }
    }

    @Test func hashKeySignedByStrangerThrows() throws {
        let node = TestIdentity()
        let seed = Data(repeating: 5, count: 32)
        let armored = try TestIdentity().encryptSigned(
            Data(seed.base64EncodedString().utf8), to: node.recipient
        )
        #expect(throws: DecryptChainError.signatureInvalid(what: "folder hash key")) {
            _ = try DecryptChain.unlockHashKey(makeLink(hashKey: armored), nodeKeys: node.keys, addressKeys: [])
        }
    }
}

// MARK: - content-level: names

struct NameSignatureTests {
    @Test func validNameHasNoIssue() throws {
        let parent = TestIdentity()
        var me = TestIdentity()
        me.email = "me@proton.me"
        let link = makeLink(
            name: try me.encryptSigned(Data("Report.pdf".utf8), to: parent.recipient),
            email: "me@proton.me", nameEmail: "me@proton.me"
        )
        let (name, outcome) = try DecryptChain.decryptNameVerified(
            link, parentKeys: parent.keys, addressKeys: me.keys
        )
        #expect(name == "Report.pdf")
        #expect(outcome == .valid)
        let item = DriveItem(link: link, shareID: "S", decryptedName: name, signatureIssue: !outcome.isValid)
        #expect(!item.signatureIssue)
    }

    @Test func tamperedNameSignatureFlagsItem() throws {
        // Name re-encrypted by an attacker who holds the parent key but not
        // the claimed author's address key: decrypts fine, signature fails.
        let parent = TestIdentity()
        var me = TestIdentity()
        me.email = "me@proton.me"
        let link = makeLink(
            name: try TestIdentity().encryptSigned(Data("Evil.pdf".utf8), to: parent.recipient),
            email: "me@proton.me", nameEmail: "me@proton.me"
        )
        let (name, outcome) = try DecryptChain.decryptNameVerified(
            link, parentKeys: parent.keys, addressKeys: me.keys
        )
        #expect(name == "Evil.pdf") // browsing is not blocked…
        #expect(outcome == .invalid)
        let item = DriveItem(link: link, shareID: "S", decryptedName: name, signatureIssue: !outcome.isValid)
        #expect(item.signatureIssue) // …but the row is flagged
        #expect(item.isNameDecrypted)
    }

    @Test func unsignedNameReportsMissing() throws {
        let parent = TestIdentity()
        let link = makeLink(
            name: try MessageEncrypt.encryptName("Plain", parentRecipient: parent.recipient),
            email: "me@proton.me"
        )
        let (name, outcome) = try DecryptChain.decryptNameVerified(
            link, parentKeys: parent.keys, addressKeys: TestIdentity().keys
        )
        #expect(name == "Plain")
        #expect(outcome == .missing)
    }

    @Test func anonymousNameVerifiesWithParentKey() throws {
        let parent = TestIdentity()
        let link = makeLink(name: try parent.encryptSigned(Data("Anon".utf8), to: parent.recipient))
        let (_, outcome) = try DecryptChain.decryptNameVerified(
            link, parentKeys: parent.keys, addressKeys: TestIdentity().keys
        )
        #expect(outcome == .valid)
    }

    @Test func foreignNameSignerIsUnverifiable() throws {
        let parent = TestIdentity()
        var me = TestIdentity()
        me.email = "me@proton.me"
        var other = TestIdentity()
        other.email = "other@proton.me"
        let link = makeLink(
            name: try other.encryptSigned(Data("Shared".utf8), to: parent.recipient),
            email: "other@proton.me", nameEmail: "other@proton.me"
        )
        let (_, outcome) = try DecryptChain.decryptNameVerified(
            link, parentKeys: parent.keys, addressKeys: me.keys
        )
        #expect(outcome == .noVerifier)
    }
}

// MARK: - content-level: downloads

struct DownloadSignatureTests {
    private func blockHashesB64(_ hashes: [Data]) -> [String] { hashes.map { $0.base64EncodedString() } }

    @Test func manifestValidMissingInvalid() throws {
        let author = TestIdentity()
        let hashes = [Data(repeating: 1, count: 32), Data(repeating: 2, count: 32)]
        let variants = try FileDownload.manifestVariants(
            blockHashesB64: blockHashesB64(hashes), thumbnails: [], legacyThumbnailHash: nil
        )
        let good = try author.sign(FileUpload.manifestInput(hashes: hashes))
        #expect(try FileDownload.verifyManifest(
            signature: good, variants: variants, signerPoints: [author.point]
        ) == .valid)

        // Signature over a DIFFERENT block list (one block swapped).
        let swapped = try author.sign(FileUpload.manifestInput(hashes: [hashes[0], Data(repeating: 9, count: 32)]))
        #expect(throws: FileDownloadError.manifestSignatureInvalid) {
            try FileDownload.verifyManifest(signature: swapped, variants: variants, signerPoints: [author.point])
        }
        // Right data, wrong signer.
        #expect(throws: FileDownloadError.manifestSignatureInvalid) {
            try FileDownload.verifyManifest(signature: good, variants: variants, signerPoints: [TestIdentity().point])
        }
        // Weak hash is never accepted.
        let weak = try author.sign(FileUpload.manifestInput(hashes: hashes), hashAlgo: 2)
        #expect(throws: FileDownloadError.manifestSignatureInvalid) {
            try FileDownload.verifyManifest(signature: weak, variants: variants, signerPoints: [author.point])
        }
        #expect(throws: FileDownloadError.manifestSignatureMissing) {
            try FileDownload.verifyManifest(signature: nil, variants: variants, signerPoints: [author.point])
        }
        // Foreign signer (no verifier) is reported, not thrown.
        #expect(try FileDownload.verifyManifest(signature: good, variants: variants, signerPoints: []) == .noVerifier)
    }

    @Test func manifestIncludesThumbnailsSortedByType() throws {
        let author = TestIdentity()
        let block = Data(repeating: 3, count: 32)
        let thumb = Data(repeating: 7, count: 32)
        let preview = Data(repeating: 8, count: 32)
        // C# SDK order: thumbnails by Type (1 then 2), then blocks.
        let signed = try author.sign(thumb + preview + block)
        let variants = try FileDownload.manifestVariants(
            blockHashesB64: [block.base64EncodedString()],
            thumbnails: [
                RevisionThumbnail(type: 2, hash: preview.base64EncodedString()),
                RevisionThumbnail(type: 1, hash: thumb.base64EncodedString()),
            ],
            legacyThumbnailHash: nil
        )
        #expect(try FileDownload.verifyManifest(signature: signed, variants: variants, signerPoints: [author.point]) == .valid)
    }

    @Test func revisionDecodesSignatureEmailAndThumbnails() throws {
        let json = """
        {"ID":"r1","Blocks":[],"ManifestSignature":"sig","SignatureEmail":"me@proton.me",
         "Thumbnails":[{"ThumbnailID":"t","Type":1,"Hash":"AQI=","Size":10}]}
        """
        let rev = try JSONDecoder().decode(RevisionDetail.self, from: Data(json.utf8))
        #expect(rev.signatureEmail == "me@proton.me")
        #expect(rev.thumbnails.count == 1)
        #expect(rev.thumbnails.first?.hash == "AQI=")
    }

    @Test func contentKeySignatureVariants() throws {
        let node = TestIdentity()
        let sessionKey = Data(repeating: 0x42, count: 32)
        let packet = Data("raw-pkesk".utf8)
        // Upstream: signature over the session key bytes.
        #expect(try FileDownload.verifyContentKey(
            signature: try node.sign(sessionKey), sessionKey: sessionKey,
            packetRaw: packet, signerPoints: [node.point]
        ) == .valid)
        // Nucleon F4.3 uploads: signature over the raw packet bytes.
        #expect(try FileDownload.verifyContentKey(
            signature: try node.sign(packet), sessionKey: sessionKey,
            packetRaw: packet, signerPoints: [node.point]
        ) == .valid)
        // Optional upstream: missing is reported, not thrown.
        #expect(try FileDownload.verifyContentKey(
            signature: nil, sessionKey: sessionKey, packetRaw: packet, signerPoints: [node.point]
        ) == .missing)
        #expect(throws: FileDownloadError.contentKeySignatureInvalid) {
            try FileDownload.verifyContentKey(
                signature: try TestIdentity().sign(sessionKey), sessionKey: sessionKey,
                packetRaw: packet, signerPoints: [node.point]
            )
        }
    }

    @Test func blockSignaturesVerifiedDuringReassembly() throws {
        let node = TestIdentity()
        let author = TestIdentity()
        let key = Data(repeating: 0x11, count: 32)
        let plain = Data("block-plaintext".utf8)
        let enc = try FileUpload.encryptBlock(plain, contentKey: key)
        let hash = try FileUpload.blockHash(enc)
        let check = FileDownload.BlockSignatureCheck(
            nodeCandidates: node.keys.compactMap(\.candidate), signerPoints: [author.point]
        )
        func encSig(signer: TestIdentity, over data: Data) throws -> String {
            let packet = try FileUpload.blockSignaturePacket(
                blockHash: data, signerSeedLE: signer.ed.rawRepresentation,
                signerKeyID: Data(signer.edFP.suffix(8)), signerFingerprint: signer.edFP
            )
            return try FileUpload.encryptSignaturePacket(packet, nodeRecipient: node.recipient)
        }
        func block(_ sig: String?) -> FileDownload.FetchedBlock {
            FileDownload.FetchedBlock(
                index: 1, encrypted: enc, expectedHashB64: hash.base64EncodedString(), encSignature: sig
            )
        }
        // Nucleon variant (signature over the encrypted-block hash).
        #expect(try FileDownload.reassemble(
            blocks: [block(try encSig(signer: author, over: hash))], contentKey: key, signatures: check
        ) == plain)
        // Upstream variant (signature over the plaintext block).
        #expect(try FileDownload.reassemble(
            blocks: [block(try encSig(signer: author, over: plain))], contentKey: key, signatures: check
        ) == plain)
        // Forged by another key → the download fails.
        #expect(throws: FileDownloadError.blockSignatureInvalid(index: 1)) {
            _ = try FileDownload.reassemble(
                blocks: [block(try encSig(signer: TestIdentity(), over: plain))], contentKey: key, signatures: check
            )
        }
        // Not decryptable by the node key → fails too.
        #expect(throws: FileDownloadError.blockSignatureInvalid(index: 1)) {
            _ = try FileDownload.reassemble(
                blocks: [block(try author.encryptSigned(plain, to: TestIdentity().recipient))],
                contentKey: key, signatures: check
            )
        }
    }

    @Test func userFacingMessagesForSignatureFailures() {
        #expect(UserFacingError.message(for: FileDownloadError.manifestSignatureInvalid).contains("signature"))
        #expect(UserFacingError.message(for: FileDownloadError.manifestSignatureMissing).contains("not signed"))
        #expect(UserFacingError.message(for: DecryptChainError.signatureMissing(what: "node passphrase"))
            .contains("node passphrase"))
    }
}

// MARK: - signer selection

struct SignerSelectionTests {
    @Test func emailSelectsAddressKeys() {
        var a = TestIdentity()
        a.email = "a@proton.me"
        var b = TestIdentity()
        b.email = "b@proton.me"
        let all = a.keys + b.keys
        let fallback = [Data(repeating: 1, count: 32)]
        #expect(SignatureVerification.signerPoints(claimedEmail: "B@proton.me", addressKeys: all, anonymousFallback: fallback) == [b.point])
        #expect(SignatureVerification.signerPoints(claimedEmail: nil, addressKeys: all, anonymousFallback: fallback) == fallback)
        #expect(SignatureVerification.signerPoints(claimedEmail: "", addressKeys: all, anonymousFallback: fallback) == fallback)
        #expect(SignatureVerification.signerPoints(claimedEmail: "c@x.me", addressKeys: all, anonymousFallback: fallback).isEmpty)
    }
}
