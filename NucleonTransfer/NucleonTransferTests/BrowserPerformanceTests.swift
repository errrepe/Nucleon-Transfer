// Nucleon Transfer — F8.3-P3 browser & listing performance (Swift Testing).
// The fused visible-rows pipeline orders exactly like the old one, the
// per-folder memo recomputes only on a real change, paging stops on a
// short page, and the parallel name decrypt keeps order and the F8.1-S2
// signature flag. The timing comparison only runs with NT_BENCH=1
// (release: `swift test -c release -Xswiftc -enable-testing`).
import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - fixtures

private func row(_ index: Int, folder: Bool, name: String) -> DriveItem {
    DriveItem(
        id: "id-\(index)", shareID: "S", parentLinkID: "P", name: name,
        isNameDecrypted: true, kind: folder ? .folder : .file, size: Int64(index % 97),
        modified: Date(timeIntervalSince1970: 1_700_000_000 + TimeInterval(index % 13)),
        mimeType: nil
    )
}

/// Deterministic mixed listing with duplicate names/sizes (stability matters).
private func listing(_ count: Int) -> [DriveItem] {
    (0..<count).map { i in
        row(i, folder: i % 7 == 0, name: "File \((i * 7919) % (count / 2 + 1)) Ä.txt")
    }
}

/// The pre-P3 pipeline, verbatim: filter, full sort, two filter passes.
private func legacyVisible(
    _ items: [DriveItem], query: String, using comparators: [KeyPathComparator<DriveItem>]
) -> [DriveItem] {
    let filtered = DriveItemOrdering.filtered(items, query: query)
    let ordered = filtered.sorted(using: comparators)
    return ordered.filter(\.isFolder) + ordered.filter { !$0.isFolder }
}

private let nameAsc = [KeyPathComparator<DriveItem>(\.name, comparator: .localizedStandard)]

// MARK: - ordering + memo

struct VisibleItemsTests {
    @Test(arguments: [
        [KeyPathComparator<DriveItem>(\.name, comparator: .localizedStandard)],
        [KeyPathComparator<DriveItem>(\.name, comparator: .localizedStandard, order: .reverse)],
        [KeyPathComparator<DriveItem>(\.size), KeyPathComparator<DriveItem>(\.name, comparator: .localizedStandard)],
        [KeyPathComparator<DriveItem>(\.modified, order: .reverse)],
        [],
    ])
    func fusedPipelineMatchesLegacy(_ comparators: [KeyPathComparator<DriveItem>]) {
        let items = listing(600)
        for query in ["", "  ", "file 1", "ä"] {
            #expect(
                DriveItemOrdering.visible(items, query: query, using: comparators).map(\.id)
                    == legacyVisible(items, query: query, using: comparators).map(\.id)
            )
        }
    }

    @Test func memoRecomputesOnlyOnChange() {
        var memo = VisibleItemsMemo()
        let items = listing(50)
        let first = memo.items(from: items, version: 1, query: "", using: nameAsc)
        _ = memo.items(from: items, version: 1, query: "", using: nameAsc)
        _ = memo.items(from: items, version: 1, query: "  ", using: nameAsc) // same trimmed query
        #expect(memo.computeCount == 1)
        #expect(first.map(\.id) == DriveItemOrdering.visible(items, query: "", using: nameAsc).map(\.id))

        let reversed = [KeyPathComparator<DriveItem>(\.name, comparator: .localizedStandard, order: .reverse)]
        let byReverse = memo.items(from: items, version: 1, query: "", using: reversed)
        #expect(memo.computeCount == 2)
        #expect(byReverse.map(\.id) == DriveItemOrdering.visible(items, query: "", using: reversed).map(\.id))

        let filtered = memo.items(from: items, version: 1, query: "file 1", using: reversed)
        #expect(memo.computeCount == 3)
        #expect(filtered.allSatisfy { $0.name.localizedStandardContains("file 1") })

        let fewer = Array(items.prefix(10))
        let reloaded = memo.items(from: fewer, version: 2, query: "file 1", using: reversed)
        #expect(memo.computeCount == 4)
        #expect(Set(reloaded.map(\.id)).isSubset(of: Set(fewer.map(\.id))))
    }
}

// MARK: - paging

/// Records requested pages; serves `total` rows in `pageSize` pages.
private actor PageServer {
    let total: Int
    let pageSize: Int
    private(set) var requested: [Int] = []

    init(total: Int, pageSize: Int) {
        self.total = total
        self.pageSize = pageSize
    }

    func page(_ page: Int) -> [Int] {
        requested.append(page)
        let start = page * pageSize
        guard start < total else { return [] }
        return Array(start..<min(start + pageSize, total))
    }
}

struct ListChildrenPagingTests {
    @Test(arguments: [
        (0, [0]),           // empty folder: one request
        (99, [0]),          // short first page is the last page (was 2 requests)
        (100, [0, 1]),      // exact full page needs one empty probe
        (250, [0, 1, 2]),   // full, full, short
        (300, [0, 1, 2, 3]),
    ])
    func stopsOnShortPage(total: Int, expectedPages: [Int]) async {
        let server = PageServer(total: total, pageSize: 100)
        let all = await DriveClient.collectPages(pageSize: 100) { await server.page($0) }
        #expect(all == Array(0..<total))
        #expect(await server.requested == expectedPages)
    }

    @Test func errorPropagates() async {
        struct Boom: Error {}
        await #expect(throws: Boom.self) {
            _ = try await DriveClient.collectPages(pageSize: 10) { page -> [Int] in
                if page == 1 { throw Boom() }
                return Array(0..<10)
            }
        }
    }
}

// MARK: - parallel name decrypt

/// Throwaway #22 signing + #18 encryption identity (as unlocked keys).
private struct Identity {
    let ed = Curve25519.Signing.PrivateKey()
    let x = Curve25519.KeyAgreement.PrivateKey()
    let edFP = Data((0..<20).map { _ in UInt8.random(in: .min ... .max) })
    let xFP = Data((0..<20).map { _ in UInt8.random(in: .min ... .max) })
    let email: String

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

    func encryptSigned(_ name: String, to recipient: EncryptRecipient) throws -> String {
        try MessageEncrypt.encryptSigned(
            plaintext: Data(name.utf8), recipient: recipient,
            signerSeedLE: ed.rawRepresentation, signerKeyID: Data(edFP.suffix(8)),
            signerFingerprint: edFP, hashAlgo: 8, salt: DetachedSign.freshSalt(16)
        )
    }
}

private func link(_ index: Int, name: String) -> DriveLink {
    DriveLink(
        linkID: "L\(index)", parentLinkID: "P", type: index % 5 == 0 ? 1 : 2, name: name,
        hash: nil, size: 0, state: 1, mimeType: nil, createTime: 0, modifyTime: 0,
        expirationTime: nil, nodeKey: nil, nodePassphrase: nil,
        nodePassphraseSignature: nil, signatureEmail: "me@proton.me",
        nameSignatureEmail: "me@proton.me", xAttr: nil, fileProperties: nil,
        folderProperties: nil
    )
}

/// `count` links: every 3rd name signed by a stranger (signature issue),
/// every 11th undecryptable, the rest validly signed by `me`.
private func encryptedLinks(
    _ count: Int, parent: Identity, me: Identity
) throws -> [DriveLink] {
    let stranger = Identity(email: "me@proton.me")
    return try (0..<count).map { i in
        if i % 11 == 0 { return link(i, name: "not-armored") }
        let signer = i % 3 == 0 ? stranger : me
        return link(i, name: try signer.encryptSigned("Name \(i)", to: parent.recipient))
    }
}

struct ParallelNameDecryptTests {
    @Test func parallelKeepsOrderAndSignatureFlags() async throws {
        let parent = Identity(email: "parent@proton.me")
        let me = Identity(email: "me@proton.me")
        let links = try encryptedLinks(45, parent: parent, me: me)
        let parallel = await DriveListing.decryptNames(
            links, shareID: "S", parentKeys: parent.keys, addressKeys: me.keys, maxWidth: 4
        )
        let serial = await DriveListing.decryptNames(
            links, shareID: "S", parentKeys: parent.keys, addressKeys: me.keys, maxWidth: 1
        )
        #expect(parallel == serial)
        #expect(parallel.map(\.id) == links.map(\.linkID))
        for (i, item) in parallel.enumerated() {
            if i % 11 == 0 {
                #expect(!item.isNameDecrypted)
                #expect(item.name == "Encrypted Item")
                #expect(!item.signatureIssue)
            } else {
                #expect(item.name == "Name \(i)")
                #expect(item.signatureIssue == (i % 3 == 0))
            }
            #expect(item.isFolder == (i % 5 == 0))
        }
    }

    @Test func smallAndEmptyListings() async throws {
        let parent = Identity(email: "parent@proton.me")
        let me = Identity(email: "me@proton.me")
        let empty = await DriveListing.decryptNames(
            [], shareID: "S", parentKeys: parent.keys, addressKeys: me.keys
        )
        #expect(empty.isEmpty)
        let links = try encryptedLinks(3, parent: parent, me: me)
        let items = await DriveListing.decryptNames(
            links, shareID: "S", parentKeys: parent.keys, addressKeys: me.keys, maxWidth: 16
        )
        #expect(items.map(\.id) == ["L0", "L1", "L2"])
    }
}

// MARK: - timing (opt-in)

@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["NT_BENCH"] == "1"))
struct BrowserPerformanceBenchmarks {
    private func millis(_ runs: Int, _ body: () async -> Void) async -> Double {
        let clock = ContinuousClock()
        let elapsed = await clock.measure {
            for _ in 0..<runs { await body() }
        }
        let c = elapsed.components
        return (Double(c.seconds) * 1e3 + Double(c.attoseconds) / 1e15) / Double(runs)
    }

    @Test func sort5k() async {
        let items = listing(5_000)
        let legacy = await millis(10) { _ = legacyVisible(items, query: "", using: nameAsc) }
        let fused = await millis(10) { _ = DriveItemOrdering.visible(items, query: "", using: nameAsc) }
        var memo = VisibleItemsMemo()
        _ = memo.items(from: items, version: 1, query: "", using: nameAsc)
        let cached = await millis(1_000) {
            _ = memo.items(from: items, version: 1, query: "", using: nameAsc)
        }
        print(String(format: "BENCH sort5k legacy=%.2fms fused=%.2fms memoHit=%.2fus",
                     legacy, fused, cached * 1_000))
    }

    @Test func decrypt200() async throws {
        let parent = Identity(email: "parent@proton.me")
        let me = Identity(email: "me@proton.me")
        let links = try encryptedLinks(200, parent: parent, me: me)
        let serial = await millis(5) {
            _ = await DriveListing.decryptNames(
                links, shareID: "S", parentKeys: parent.keys, addressKeys: me.keys, maxWidth: 1)
        }
        let parallel = await millis(5) {
            _ = await DriveListing.decryptNames(
                links, shareID: "S", parentKeys: parent.keys, addressKeys: me.keys)
        }
        print(String(format: "BENCH decrypt200 serial=%.2fms parallel=%.2fms cores=%d",
                     serial, parallel, ProcessInfo.processInfo.activeProcessorCount))
    }
}
