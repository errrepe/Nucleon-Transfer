// Nucleon Transfer — F8.1-S7 secret wiping tests (Swift Testing).
// SecureBytes zeroes owned buffers in place; copy-on-write keeps it from
// ever scribbling over a value someone else still holds. KeyringCache.lock()
// drops every seed.
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

struct SecureBytesTests {

    @Test func wipesByteArray() {
        var buf: [UInt8] = Array(1...64)
        SecureBytes.wipe(&buf)
        #expect(buf.count == 64)
        #expect(buf.allSatisfy { $0 == 0 })
    }

    @Test func wipesWordArray() {
        var words: [UInt32] = [0xDEAD_BEEF, 0x0123_4567, .max]
        SecureBytes.wipe(&words)
        #expect(words == [0, 0, 0])
    }

    @Test(arguments: [4, 14, 32, 4096])   // inline and heap-backed Data
    func wipesData(count: Int) {
        var data = Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &+ 1) })
        SecureBytes.wipe(&data)
        #expect(data.count == count)
        #expect(data.allSatisfy { $0 == 0 })
    }

    @Test func wipesDataSlice() {
        var slice = Data(repeating: 0xAA, count: 64)[8..<40]
        SecureBytes.wipe(&slice)
        #expect(slice.count == 32)
        #expect(slice.allSatisfy { $0 == 0 })
    }

    @Test func emptyBuffersAreNoOps() {
        var bytes: [UInt8] = []
        var data = Data()
        SecureBytes.wipe(&bytes)
        SecureBytes.wipe(&data)
        #expect(bytes.isEmpty && data.isEmpty)
    }

    @Test func sharedCopyIsNeverCorrupted() {
        // Wiping a copy must not reach into storage another live value owns.
        let original = Data(repeating: 0x5A, count: 64)
        var copy = original
        SecureBytes.wipe(&copy)
        #expect(copy.allSatisfy { $0 == 0 })
        #expect(original.allSatisfy { $0 == 0x5A })
    }

    @Test func wipeSeedsZeroesEveryKey() {
        var keys = (0..<3).map { i in
            KeyringCache.UnlockedKey(keyID: "k\(i)", algo: 22, seed: Data(repeating: 0x77, count: 32),
                                     fingerprint: Data(), kdfHash: 8, kdfCipher: 9, curveOIDBody: Data())
        }
        keys.wipeSeeds()
        #expect(keys.allSatisfy { $0.seed.count == 32 && $0.seed.allSatisfy { $0 == 0 } })
    }

    @Test func bcryptOutputUnchangedByWiping() throws {
        // jBCrypt canonical vector (empty password): wiping internals must
        // not change the digest.
        let out = try ProtonBcryptHasher().hash(password: Data(),
                                                dotSlashSalt: "$2a$06$DCq7YPn5Rq63x1Lad4cll.")
        #expect(String(decoding: out, as: UTF8.self).hasSuffix("TV4S6ytwfsfvkgY8jIucDrjc8deX1s."))
    }

    @Test func keyringLockDropsSeeds() async throws {
        // A real locked key: FolderCreate generates a NodeKey + passphrase.
        let parentX = Curve25519.KeyAgreement.PrivateKey()
        let parentKeys = [KeyringCache.UnlockedKey(
            keyID: "parent#18", algo: 18, seed: parentX.rawRepresentation,
            fingerprint: Data(repeating: 0x11, count: 20), kdfHash: 8, kdfCipher: 7,
            curveOIDBody: NodeKeyGen.ecdhOID
        )]
        let addressKeys = [KeyringCache.UnlockedKey(
            keyID: "addr#22", algo: 22, seed: Curve25519.Signing.PrivateKey().rawRepresentation,
            fingerprint: Data(repeating: 0x22, count: 20), kdfHash: 8, kdfCipher: 9,
            curveOIDBody: NodeKeyGen.edOID
        )]
        let (request, node) = try FolderCreate.buildRequest(
            name: "n", parentLinkID: "p", parentKeys: parentKeys,
            parentHashKey: Data(repeating: 1, count: 32), addressKeys: addressKeys,
            signatureAddress: "test@proton.me", xAttrPlaintext: Data("{}".utf8)
        )

        let cache = KeyringCache(sessions: SessionManager())
        let unlocked = try await cache.unlockSecretKeys(armored: request.nodeKey,
                                                        passphrase: node.passphrase, idPrefix: "t")
        #expect(unlocked.count == 2)
        for key in unlocked { #expect(await cache.seed(for: key.keyID) != nil) }

        await cache.lock()
        for key in unlocked { #expect(await cache.seed(for: key.keyID) == nil) }
        // Our own copies were never shared-mutated by the wipe.
        #expect(unlocked.allSatisfy { $0.seed.contains { $0 != 0 } })
    }
}
