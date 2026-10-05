// Nucleon Transfer — drive tree listing service (F7/S1.3).
// Network glue between DriveClient and NodeKeyResolver: roots() classifies
// the browsable shares (ShareCatalog), children(of:) lists a folder's active
// links with decrypted names and feeds the resolver's link cache. Name
// decryption is CPU work — it runs on this actor, never on the main thread.
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
    /// `listChildren` already aggregates all pages (stops on first empty).
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
    /// Nonisolated async: the decrypt work runs on the CALLER's executor —
    /// both callers are actors, so CPU work never touches the main thread.
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
        let addressKeys = resolver.addressKeys
        return links.map { link in
            // F8.1-S2: the name's inline signature is checked; a failure
            // flags the row (warning badge) instead of hiding it.
            let decrypted = try? DecryptChain.decryptNameVerified(
                link, parentKeys: keys, addressKeys: addressKeys
            )
            return DriveItem(
                link: link,
                shareID: shareID,
                decryptedName: decrypted?.name,
                signatureIssue: decrypted.map { !$0.signature.isValid } ?? false
            )
        }
    }
}

extension DriveListing: DriveListingProviding {}
