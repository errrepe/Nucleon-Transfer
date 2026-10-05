// Nucleon Transfer — one row in a drive listing (file or folder).
// Built from a wire DriveLink plus its decrypted name (F3b chain); pure
// value type for table/outline display.
import Foundation

struct DriveItem: Identifiable, Hashable, Sendable {
    enum Kind: Hashable, Sendable { case folder, file }

    /// The link's `LinkID` — unique within its share.
    let id: String
    let shareID: String
    let parentLinkID: String?
    /// Decrypted name, or "Encrypted Item" when the name could not be read.
    let name: String
    let isNameDecrypted: Bool
    let kind: Kind
    /// Always 0 for folders (their wire size is ciphertext size — backlog B2).
    let size: Int64
    let modified: Date
    let mimeType: String?
    /// The item's name signature could not be verified (missing, invalid,
    /// weak hash or unknown signer — F8.1-S2). Browsing continues; the UI
    /// shows a warning badge, like the official clients' "signature could
    /// not be verified" state.
    var signatureIssue: Bool = false

    var isFolder: Bool { kind == .folder }
    var fileExtension: String { (name as NSString).pathExtension.lowercased() }
    var location: DriveLocation { .init(shareID: shareID, linkID: id, name: name) }
}

extension DriveItem {
    /// Builds a row from a wire link. `decryptedName == nil` means the F3b
    /// chain could not read the name — the row still renders, flagged.
    /// `signatureIssue` flags a decrypted name whose signature failed.
    init(link: DriveLink, shareID: String, decryptedName: String?, signatureIssue: Bool = false) {
        self.init(
            id: link.linkID,
            shareID: shareID,
            parentLinkID: link.parentLinkID,
            name: decryptedName ?? String(localized: "Encrypted Item", comment: "Name shown for an item whose name couldn’t be decrypted"),
            isNameDecrypted: decryptedName != nil,
            kind: link.isFolder ? .folder : .file,
            size: link.isFolder ? 0 : link.size,
            modified: Date(timeIntervalSince1970: TimeInterval(link.modifyTime)),
            mimeType: link.mimeType,
            signatureIssue: signatureIssue
        )
    }
}
