// Nucleon Transfer — NodeKeyResolver suite (S1.2, Swift Testing).
// Fake source + fake unlocker: no real crypto, no network. Fake keys are
// marked by `keyID` = the link/share id they claim to unlock, and the fake
// unlockNode records which parent candidates it received (via the mark
// embedded in each key's fingerprint) so the parent-chain walk is asserted.
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - fakes

/// In-memory DriveKeyMaterialSource: scripted shares/links + call counters.
final class FakeSource: DriveKeyMaterialSource, @unchecked Sendable {
    private let lock = NSLock()
    private var shares: [String: DriveShare] = [:]
    private var links: [String: DriveLink] = [:]
    private(set) var getShareCalls = 0
    private(set) var getLinkCalls: [String] = []
    /// Artificial latency so concurrent callers overlap (single-flight test).
    var delayNanoseconds: UInt64 = 0

    func addShare(_ share: DriveShare) {
        lock.withLock { shares[share.shareID] = share }
    }

    func addLink(_ link: DriveLink) {
        lock.withLock { links[link.linkID] = link }
    }

    var linkFetchCount: Int { lock.withLock { getLinkCalls.count } }
    func fetches(of linkID: String) -> Int {
        lock.withLock { getLinkCalls.filter { $0 == linkID }.count }
    }

    func getShare(_ shareID: String) async throws -> DriveShare {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        return try lock.withLock {
            getShareCalls += 1
            guard let share = shares[shareID] else {
                throw ProtonAPIError.api(code: 404, message: "no such share")
            }
            return share
        }
    }

    func getLink(shareID: String, linkID: String) async throws -> DriveLink {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        return try lock.withLock {
            getLinkCalls.append(linkID)
            guard let link = links[linkID] else {
                throw ProtonAPIError.api(code: 404, message: "no such link")
            }
            return link
        }
    }
}

/// Records which parent candidates each unlock call received.
final class UnlockSpy: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var shareCalls = 0
    private(set) var nodeCalls: [(linkID: String, parentMarks: [String])] = []

    func recordShare() { lock.withLock { shareCalls += 1 } }

    func recordNode(_ linkID: String, _ candidates: [DecryptCandidate]) {
        lock.withLock {
            nodeCalls.append((linkID, candidates.map { Self.mark($0.fingerprint) }))
        }
    }

    func calls(for linkID: String) -> [String]? {
        lock.withLock { nodeCalls.first { $0.linkID == linkID }?.parentMarks }
    }

    /// A key's mark is its id embedded in the 20-byte fingerprint.
    static func mark(_ fingerprint: Data) -> String {
        String(decoding: fingerprint.prefix(while: { $0 != 0 }), as: UTF8.self)
    }
}

// MARK: - builders

/// Fake unlocked key whose candidate fingerprint carries `mark` (≤20 chars),
/// so tests can verify WHICH keys were used as parent candidates.
func fakeKey(_ mark: String) -> KeyringCache.UnlockedKey {
    var fp = Data(mark.utf8)
    if fp.count < 20 { fp += Data(repeating: 0, count: 20 - fp.count) }
    return KeyringCache.UnlockedKey(
        keyID: mark, algo: 18, seed: Data(repeating: 7, count: 32),
        fingerprint: Data(fp.prefix(20)), kdfHash: 8, kdfCipher: 7,
        curveOIDBody: Data([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
    )
}

/// Unlocker that "unlocks" by marking: shares get keys marked
/// `sharekeys-<shareID>`, nodes get keys marked with their linkID, and the
/// spy records every call's parent candidates.
func fakeUnlocker(
    spy: UnlockSpy,
    hashKeyFor: (@Sendable (String) -> Data?)? = nil
) -> NodeUnlocker {
    NodeUnlocker(
        unlockShare: { share, _ in
            spy.recordShare()
            return [fakeKey("sharekeys-\(share.shareID)")]
        },
        unlockNode: { link, candidates, _ in
            spy.recordNode(link.linkID, candidates)
            return [fakeKey(link.linkID)]
        },
        folderHashKey: { link, _, _ in
            let seed = hashKeyFor?(link.linkID) ?? Data(repeating: 9, count: 32)
            guard !seed.isEmpty else {
                throw TransferFailure.permanent("folder has no NodeHashKey")
            }
            return seed
        }
    )
}

func makeShare(_ shareID: String, root: String = "R") -> DriveShare {
    DriveShare(
        shareID: shareID, linkID: root, volumeID: nil, type: 1, state: 1,
        creator: "creator@x", addressID: "addr-1", addressKeyID: nil,
        key: "k", passphrase: "p", passphraseSignature: nil
    )
}

func makeLink(_ id: String, parent: String?, hashKey: Bool = true) -> DriveLink {
    DriveLink(
        linkID: id, parentLinkID: parent, type: 1, name: "enc", hash: nil,
        size: 0, state: 1, mimeType: nil, createTime: 0, modifyTime: 0,
        expirationTime: nil, nodeKey: "k", nodePassphrase: "p",
        nodePassphraseSignature: nil, signatureEmail: nil, xAttr: nil,
        fileProperties: nil,
        folderProperties: hashKey ? FolderProperties(nodeHashKey: "h") : nil
    )
}

func makeResolver(
    source: FakeSource, spy: UnlockSpy, unlocker: NodeUnlocker? = nil
) -> NodeKeyResolver {
    NodeKeyResolver(
        source: source, addressKeys: [fakeKey("addr")],
        unlocker: unlocker ?? fakeUnlocker(spy: spy)
    )
}

// MARK: - tests

struct NodeKeyResolverTests {
    /// Chain: share S → root R → folder A → folder B.
    private func seededSource() -> FakeSource {
        let source = FakeSource()
        source.addShare(makeShare("S", root: "R"))
        source.addLink(makeLink("R", parent: nil))
        source.addLink(makeLink("A", parent: "R"))
        source.addLink(makeLink("B", parent: "A"))
        return source
    }

    @Test func rootUnlocksWithShareKeys() async throws {
        let source = seededSource()
        let spy = UnlockSpy()
        let resolver = makeResolver(source: source, spy: spy)
        let keys = try await resolver.nodeKeys(shareID: "S", linkID: "R")
        #expect(keys.map(\.keyID) == ["R"])
        // Root's node passphrase was opened with the SHARE keyring.
        #expect(spy.calls(for: "R") == ["sharekeys-S"])
        #expect(spy.shareCalls == 1)
    }

    @Test func chainUnlocksEachLevelWithParentKeys() async throws {
        let source = seededSource()
        let spy = UnlockSpy()
        let resolver = makeResolver(source: source, spy: spy)
        let keys = try await resolver.nodeKeys(shareID: "S", linkID: "B")
        #expect(keys.map(\.keyID) == ["B"])
        // B unlocked with A's keys, A with the root's, root with share keys.
        #expect(spy.calls(for: "B") == ["A"])
        #expect(spy.calls(for: "A") == ["R"])
        #expect(spy.calls(for: "R") == ["sharekeys-S"])
        // One fetch per link, one share fetch — the whole walk happened once.
        #expect(source.getLinkCalls.sorted() == ["A", "B", "R"])
        #expect(source.getShareCalls == 1)
    }

    @Test func memoizedNodeKeysSkipGetLink() async throws {
        let source = seededSource()
        let resolver = makeResolver(source: source, spy: UnlockSpy())
        _ = try await resolver.nodeKeys(shareID: "S", linkID: "B")
        _ = try await resolver.nodeKeys(shareID: "S", linkID: "B")
        _ = try await resolver.folder(shareID: "S", linkID: "B")
        #expect(source.fetches(of: "B") == 1)
        #expect(source.fetches(of: "A") == 1)
        #expect(source.getShareCalls == 1)
    }

    @Test func rememberedLinksSkipGetLink() async throws {
        let source = seededSource()
        let spy = UnlockSpy()
        let resolver = makeResolver(source: source, spy: spy)
        await resolver.remember([makeLink("R", parent: nil), makeLink("A", parent: "R")])
        let keys = try await resolver.nodeKeys(shareID: "S", linkID: "A")
        #expect(keys.map(\.keyID) == ["A"])
        #expect(source.linkFetchCount == 0) // both links came from the cache
        #expect(source.getShareCalls == 1) // share material still fetched
    }

    @Test func concurrentCallsShareOneInFlightFetch() async throws {
        let source = seededSource()
        source.delayNanoseconds = 100_000_000 // 100ms: all callers overlap
        let resolver = makeResolver(source: source, spy: UnlockSpy())
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    _ = try await resolver.nodeKeys(shareID: "S", linkID: "B")
                }
            }
            try await group.waitForAll()
        }
        // Per-node single-flight: each link fetched exactly once despite
        // 10 concurrent entry points, and the share was fetched once.
        #expect(source.fetches(of: "B") == 1)
        #expect(source.fetches(of: "A") == 1)
        #expect(source.fetches(of: "R") == 1)
        #expect(source.getShareCalls == 1)
    }

    @Test func registeredFolderNeedsNoFetch() async throws {
        let source = seededSource()
        let resolver = makeResolver(source: source, spy: UnlockSpy())
        let ctx = NodeKeyResolver.FolderContext(
            shareID: "S", linkID: "F", keys: [fakeKey("F")],
            hashKey: Data(repeating: 1, count: 32),
            addressID: "addr-1", signatureEmail: "creator@x"
        )
        await resolver.register(createdFolder: ctx)
        let got = try await resolver.folder(shareID: "S", linkID: "F")
        #expect(got.linkID == "F")
        #expect(got.keys.map(\.keyID) == ["F"])
        let nodeKeys = try await resolver.nodeKeys(shareID: "S", linkID: "F")
        #expect(nodeKeys.map(\.keyID) == ["F"])
        #expect(source.linkFetchCount == 0)
        #expect(source.getShareCalls == 0)
    }

    @Test func resetClearsAllCaches() async throws {
        let source = seededSource()
        let resolver = makeResolver(source: source, spy: UnlockSpy())
        _ = try await resolver.nodeKeys(shareID: "S", linkID: "B")
        await resolver.reset()
        _ = try await resolver.nodeKeys(shareID: "S", linkID: "B")
        #expect(source.fetches(of: "B") == 2)
        #expect(source.getShareCalls == 2)
    }

    @Test func folderWithoutHashKeyFails() async throws {
        let source = FakeSource()
        source.addShare(makeShare("S", root: "R"))
        source.addLink(makeLink("R", parent: nil))
        source.addLink(makeLink("F", parent: "R", hashKey: false)) // no NodeHashKey
        let spy = UnlockSpy()
        // Real folderHashKey (the live NodeHashKey convention), fake unlocks.
        var unlocker = fakeUnlocker(spy: spy)
        unlocker.folderHashKey = NodeUnlocker.live.folderHashKey
        let resolver = makeResolver(source: source, spy: spy, unlocker: unlocker)
        await #expect(throws: TransferFailure.permanent("folder has no NodeHashKey")) {
            try await resolver.folder(shareID: "S", linkID: "F")
        }
    }
}
