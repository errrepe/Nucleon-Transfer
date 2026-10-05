// Nucleon Transfer — drive tree listing service (F7/S1.3).
// Network glue between DriveClient and NodeKeyResolver: roots() classifies
// the browsable shares (ShareCatalog), children(of:) lists a folder's active
// links with decrypted names and feeds the resolver's link cache. Name
// decryption is CPU work — F8.3-P3 runs it in parallel chunks on the
// global executor (`decryptNames`), never on the main thread.
import Foundation

/// Read side of the drive used by the browser — the live actor and the
/// DEBUG demo fixture both conform.
protocol DriveListingProviding: AnyObject, Sendable {
    func roots() async throws -> DriveRoots
    func children(of location: DriveLocation) async throws -> [DriveItem]
}

actor DriveListing {
    private let drive: DriveClient
    private let resolver: NodeKeyResolver

    init(drive: DriveClient, resolver: NodeKeyResolver) {
        self.drive = drive
        self.resolver = resolver
    }

    /// Volumes + shares → classified roots (ShareCatalog). The volume share
    /// IDs pick the canonical main share when several `.main` rows exist.
    func roots() async throws -> DriveRoots {
        let volumes = try await drive.listVolumes()
        let mainShareIDs = Set(volumes.map(\.share.shareID))
        let metas = try await drive.listShares()
        return ShareCatalog.roots(from: metas, mainShareIDs: mainShareIDs)
    }

    /// Active children of a folder with decrypted names.
    /// `listChildren` already aggregates all pages (stops on a short page).
    func children(of location: DriveLocation) async throws -> [DriveItem] {
        try await Self.decryptedChildren(
            drive: drive, resolver: resolver,
            shareID: location.shareID, linkID: location.linkID
        )
    }

    /// Shared "list + decrypt names" pass, also used by the upload
    /// adapter's folder-conflict probe (F7.1 R4). Feeding the fetched links
    /// into the resolver's cache lets a later nodeKeys/folder lookup on a
    /// child resolve without a getLink. Names decrypt with the PARENT
    /// (location) keyring — a failure yields DriveItem's "Encrypted Item";
    /// a name whose signature fails sets DriveItem.signatureIssue.
    /// Actor state (resolver cache, keys) is only touched through the
    /// resolver's own isolation; the decrypt pass itself runs off-actor in
    /// `decryptNames` (F8.3-P3), so CPU work never touches the main thread
    /// and never serializes on the caller's actor.
    static func decryptedChildren(
        drive: DriveClient,
        resolver: NodeKeyResolver,
        shareID: String,
        linkID: String
    ) async throws -> [DriveItem] {
        let links = try await drive.listChildren(
            shareID: shareID, linkID: linkID
        ).filter(\.isActive)
        await resolver.remember(links)
        let keys = try await resolver.nodeKeys(shareID: shareID, linkID: linkID)
        return await decryptNames(
            links, shareID: shareID, parentKeys: keys, addressKeys: resolver.addressKeys
        )
    }

    /// Below this many links per task the TaskGroup overhead outweighs
    /// the parallelism — small folders decrypt in one pass.
    static let minimumChunk = 8

    /// F8.3-P3: decrypts `links`' names in parallel on the global
    /// executor — at most `maxWidth` child tasks (default: active cores),
    /// each over one contiguous chunk. Pure (no actor state); the output
    /// keeps the input order and the F8.1-S2 `signatureIssue` flag.
    @concurrent
    static func decryptNames(
        _ links: [DriveLink],
        shareID: String,
        parentKeys: [KeyringCache.UnlockedKey],
        addressKeys: [KeyringCache.UnlockedKey],
        maxWidth: Int = ProcessInfo.processInfo.activeProcessorCount
    ) async -> [DriveItem] {
        let width = min(max(maxWidth, 1), (links.count + minimumChunk - 1) / minimumChunk)
        guard width > 1 else {
            return links.map { decryptItem($0, shareID: shareID, parentKeys: parentKeys, addressKeys: addressKeys) }
        }
        let chunkSize = (links.count + width - 1) / width
        let chunks = stride(from: 0, to: links.count, by: chunkSize).map {
            Array(links[$0..<min($0 + chunkSize, links.count)])
        }
        return await withTaskGroup(of: (Int, [DriveItem]).self) { group in
            for (index, chunk) in chunks.enumerated() {
                group.addTask {
                    (index, chunk.map {
                        decryptItem($0, shareID: shareID, parentKeys: parentKeys, addressKeys: addressKeys)
                    })
                }
            }
            var parts = [[DriveItem]](repeating: [], count: chunks.count)
            for await (index, items) in group { parts[index] = items }
            return parts.flatMap { $0 }
        }
    }

    /// One row: the name's inline signature is checked (F8.1-S2); a
    /// failure flags the row (warning badge) instead of hiding it.
    private static func decryptItem(
        _ link: DriveLink,
        shareID: String,
        parentKeys: [KeyringCache.UnlockedKey],
        addressKeys: [KeyringCache.UnlockedKey]
    ) -> DriveItem {
        let decrypted = try? DecryptChain.decryptNameVerified(
            link, parentKeys: parentKeys, addressKeys: addressKeys
        )
        return DriveItem(
            link: link,
            shareID: shareID,
            decryptedName: decrypted?.name,
            signatureIssue: decrypted.map { !$0.signature.isValid } ?? false
        )
    }
}

extension DriveListing: DriveListingProviding {}
