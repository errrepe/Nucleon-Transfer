// Nucleon Transfer — single Drive key resolver (F7/S1.2).
// One actor owns all unlocked share/node key material for the session:
// share keyrings, node keys (memoized per linkID) and folder contexts
// (node keys + the folder's name-HMAC hash key). Replaces the three
// duplicated unlock chains (upload adapter, download adapter, browser
// root resolution — P6) and lets upload work under ANY existing remote
// folder, not just the root or session-created ones (P5).
// Traversal walks UP the parent chain only — never scans the tree.
import Foundation

/// Fetches Drive key material (DriveClient conforms; tests use fakes).
protocol DriveKeyMaterialSource: Sendable {
    func getShare(_ shareID: String) async throws -> DriveShare
    func getLink(shareID: String, linkID: String) async throws -> DriveLink
}

extension DriveClient: DriveKeyMaterialSource {}

/// Crypto seam so traversal/memo logic is testable without real keys.
/// `.live` wires DecryptChain: share/node passphrase signatures and the
/// folder NodeHashKey signature are mandatory (F8.1-S2, fail closed); the
/// hash key is base64-utf8 of 32 random bytes (F4.2 live-verified).
struct NodeUnlocker: Sendable {
    var unlockShare: @Sendable (DriveShare, [KeyringCache.UnlockedKey]) throws -> [KeyringCache.UnlockedKey]
    /// (link, parent candidates, allowed passphrase signer points).
    var unlockNode: @Sendable (DriveLink, [DecryptCandidate], [Data]) throws -> [KeyringCache.UnlockedKey]
    /// (folder link, its node keys, the user's address keys).
    var folderHashKey: @Sendable (DriveLink, [KeyringCache.UnlockedKey], [KeyringCache.UnlockedKey]) throws -> Data

    static let live = NodeUnlocker(
        unlockShare: { share, addressKeys in
            try DecryptChain.unlockShare(share, addressKeys: addressKeys)
        },
        unlockNode: { link, parentCandidates, signerPoints in
            try DecryptChain.unlockNode(
                link, parentCandidates: parentCandidates, signerPoints: signerPoints
            )
        },
        folderHashKey: { link, nodeKeys, addressKeys in
            try DecryptChain.unlockHashKey(link, nodeKeys: nodeKeys, addressKeys: addressKeys)
        }
    )
}

/// Session-scoped resolver for Drive key material. All state lives in this
/// actor's memory (seeds never touch disk/logs). Concurrent requests for
/// the same node share ONE in-flight task (single-flight), so a burst of
/// `nodeKeys` calls fires a single `getLink`.
actor NodeKeyResolver {
    /// Share-level context: unlocked share keyring + signer identity.
    struct ShareContext: Sendable {
        let shareID: String
        /// Root folder LinkID (its node unlocks with the share keyring).
        let rootLinkID: String
        /// Unlocked share keyring — parent candidates for the ROOT node.
        let keys: [KeyringCache.UnlockedKey]
        let addressID: String
        let signatureEmail: String
    }

    /// Fully-resolved folder: node keys + hash key (name-HMAC key for its
    /// children), plus the share's signer identity for create/upload calls.
    struct FolderContext: Sendable {
        let shareID: String
        let linkID: String
        /// This folder's node keys.
        let keys: [KeyringCache.UnlockedKey]
        /// Name-HMAC key for its children (32 bytes, decoded).
        let hashKey: Data
        let addressID: String
        let signatureEmail: String
    }

    private let source: any DriveKeyMaterialSource
    /// The user's unlocked address keys (signer candidates, F8.1-S2).
    /// Immutable + Sendable, so listings read it without hopping here.
    nonisolated let addressKeys: [KeyringCache.UnlockedKey]
    private let unlocker: NodeUnlocker

    private var shares: [String: ShareContext] = [:]
    private var nodes: [String: [KeyringCache.UnlockedKey]] = [:]
    private var folders: [String: FolderContext] = [:]
    /// Link cache fed by `remember` (listings) and by our own getLink calls.
    private var links: [String: DriveLink] = [:]
    /// Single-flight: one in-flight resolution per shareID / linkID —
    /// concurrent callers await the same task instead of re-fetching.
    private var shareTasks: [String: Task<ShareContext, Error>] = [:]
    private var nodeTasks: [String: Task<[KeyringCache.UnlockedKey], Error>] = [:]

    init(
        source: any DriveKeyMaterialSource,
        addressKeys: [KeyringCache.UnlockedKey],
        unlocker: NodeUnlocker = .live
    ) {
        self.source = source
        self.addressKeys = addressKeys
        self.unlocker = unlocker
    }

    // MARK: - public API

    /// Share context: memoized, single-flight on concurrent callers.
    func share(_ shareID: String) async throws -> ShareContext {
        if let ctx = shares[shareID] { return ctx }
        if let task = shareTasks[shareID] { return try await task.value }
        let task = Task { try await self.resolveShare(shareID) }
        shareTasks[shareID] = task
        defer { shareTasks[shareID] = nil }
        return try await task.value
    }

    /// Node keys of `linkID`: memoized, single-flight. The root unlocks
    /// with the share keyring; any other node resolves its parent's keys
    /// recursively (walk up only) and unlocks with them.
    func nodeKeys(shareID: String, linkID: String) async throws -> [KeyringCache.UnlockedKey] {
        if let keys = nodes[linkID] { return keys }
        if let task = nodeTasks[linkID] { return try await task.value }
        let task = Task { try await self.resolveNodeKeys(shareID: shareID, linkID: linkID) }
        nodeTasks[linkID] = task
        defer { nodeTasks[linkID] = nil }
        return try await task.value
    }

    /// Folder context (node keys + hash key + signer identity): memoized.
    /// Not single-flighted on its own — the expensive part (fetch + unlock)
    /// is already deduped inside `nodeKeys`; `folderHashKey` is local crypto.
    func folder(shareID: String, linkID: String) async throws -> FolderContext {
        if let ctx = folders[linkID] { return ctx }
        let shareCtx = try await share(shareID)
        let keys = try await nodeKeys(shareID: shareID, linkID: linkID)
        let link = try await self.link(shareID: shareID, linkID: linkID)
        let hashKey = try unlocker.folderHashKey(link, keys, addressKeys)
        let ctx = FolderContext(
            shareID: shareID, linkID: linkID, keys: keys, hashKey: hashKey,
            addressID: shareCtx.addressID, signatureEmail: shareCtx.signatureEmail
        )
        folders[linkID] = ctx
        return ctx
    }

    /// Caches links a listing already fetched (children/searches), so a
    /// later `nodeKeys`/`folder` resolves them without a `getLink`.
    func remember(_ newLinks: [DriveLink]) {
        for link in newLinks {
            links[link.linkID] = link
        }
    }

    /// Registers a folder created this session (post-createFolder): its
    /// keys/hash key are known-good, so lookups never fetch it.
    func register(createdFolder ctx: FolderContext) {
        folders[ctx.linkID] = ctx
        nodes[ctx.linkID] = ctx.keys
    }

    /// Wipes ALL caches and cancels in-flight resolutions (sign-out).
    /// Node seeds are zeroed in place first (F8.1-S7, best-effort): folder
    /// contexts alias the node keyrings, so they are dropped before the
    /// wipe to leave `nodes` as the last owner. Share keyrings and folder
    /// hash keys live in immutable contexts and are only dropped.
    func reset() {
        for task in shareTasks.values { task.cancel() }
        for task in nodeTasks.values { task.cancel() }
        shareTasks.removeAll()
        nodeTasks.removeAll()
        folders.removeAll()
        shares.removeAll()
        for linkID in Array(nodes.keys) {
            nodes[linkID, default: []].wipeSeeds()
        }
        nodes.removeAll()
        links.removeAll()
    }

    // MARK: - internals

    private func resolveShare(_ shareID: String) async throws -> ShareContext {
        // Re-check: a sibling task may have memoized while we suspended.
        if let ctx = shares[shareID] { return ctx }
        let share = try await source.getShare(shareID)
        let keys = try unlocker.unlockShare(share, addressKeys)
        guard let rootID = share.linkID else {
            throw TransferFailure.permanent("share has no root link")
        }
        let ctx = ShareContext(
            shareID: shareID, rootLinkID: rootID, keys: keys,
            addressID: share.addressID ?? "", signatureEmail: share.creator ?? ""
        )
        shares[shareID] = ctx
        return ctx
    }

    private func resolveNodeKeys(
        shareID: String, linkID: String
    ) async throws -> [KeyringCache.UnlockedKey] {
        // Re-check after suspension: `register` may have filled the memo.
        if let keys = nodes[linkID] { return keys }
        let ctx = try await share(shareID)
        let link = try await self.link(shareID: shareID, linkID: linkID)
        let parentKeys: [KeyringCache.UnlockedKey]
        if linkID == ctx.rootLinkID {
            // Root node's passphrase is encrypted to the share keyring.
            parentKeys = ctx.keys
        } else if let parentID = link.parentLinkID {
            // Recurse UP via the public entry point: the parent's own
            // resolution is memoized/single-flighted, so mid-chain nodes
            // share fetches across different callers. A cyclic parent chain
            // (corrupt server data) would deadlock here — same exposure the
            // old recursive adapters had; trees are acyclic by construction.
            parentKeys = try await nodeKeys(shareID: shareID, linkID: parentID)
        } else {
            // Parentless non-root link: the old adapters fell back to the
            // share keyring — keep that semantics.
            parentKeys = ctx.keys
        }
        // Passphrase signers: the link's SignatureEmail address keys, or the
        // parent key for anonymous links (DecryptChain.nodeSignerPoints).
        let keys = try unlocker.unlockNode(
            link, parentKeys.compactMap(\.candidate),
            DecryptChain.nodeSignerPoints(link, parentKeys: parentKeys, addressKeys: addressKeys)
        )
        nodes[linkID] = keys
        return keys
    }

    /// Link from the `remember` cache, else one `getLink` (then cached).
    /// Callers go through `nodeKeys`' single-flight, so each linkID is
    /// fetched at most once per resolution burst.
    private func link(shareID: String, linkID: String) async throws -> DriveLink {
        if let cached = links[linkID] { return cached }
        let fetched = try await source.getLink(shareID: shareID, linkID: linkID)
        links[linkID] = fetched
        return fetched
    }
}
