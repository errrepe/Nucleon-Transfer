// Nucleon Transfer — Drive read models.
// Shapes mirror rclone/go-proton-api share_types.go, volume_types.go and
// ProtonMail/go-proton-api link_types.go (default encoding/json => keys are
// the capitalized Go field names). IDs and names are encrypted blobs here;
// decryption lands in F3b (key hierarchy unlock).
import Foundation

// MARK: - Volumes

struct Volume: Decodable, Sendable {
    var volumeID: String
    var creationTime: Int64
    var modifyTime: Int64
    var maxSpace: Int64?
    var usedSpace: Int64
    var downloadedBytes: Int64
    var uploadedBytes: Int64
    var state: Int
    var share: VolumeShare
    var restoreStatus: Int?

    enum CodingKeys: String, CodingKey {
        case volumeID = "VolumeID"
        case creationTime = "CreationTime"
        case modifyTime = "ModifyTime"
        case maxSpace = "MaxSpace"
        case usedSpace = "UsedSpace"
        case downloadedBytes = "DownloadedBytes"
        case uploadedBytes = "UploadedBytes"
        case state = "State"
        case share = "Share"
        case restoreStatus = "RestoreStatus"
    }
}

struct VolumeShare: Decodable, Sendable {
    var shareID: String
    var linkID: String
    enum CodingKeys: String, CodingKey {
        case shareID = "ShareID"
        case linkID = "LinkID"
    }
}

struct VolumesResponse: Decodable, Sendable {
    var volumes: [Volume]
    enum CodingKeys: String, CodingKey { case volumes = "Volumes" }
}

// MARK: - Shares

struct ShareMetadata: Codable, Sendable {
    var shareID: String
    var linkID: String
    var volumeID: String
    var type: Int
    var state: Int
    var creationTime: Int64
    var modifyTime: Int64
    var creator: String?
    var flags: Int?
    var locked: Bool?
    var volumeSoftDeleted: Bool?

    enum CodingKeys: String, CodingKey {
        case shareID = "ShareID"
        case linkID = "LinkID"
        case volumeID = "VolumeID"
        case type = "Type"
        case state = "State"
        case creationTime = "CreationTime"
        case modifyTime = "ModifyTime"
        case creator = "Creator"
        case flags = "Flags"
        case locked = "Locked"
        case volumeSoftDeleted = "VolumeSoftDeleted"
    }

    init(
        shareID: String, linkID: String, volumeID: String, type: Int, state: Int,
        creationTime: Int64, modifyTime: Int64, creator: String? = nil,
        flags: Int? = nil, locked: Bool? = nil, volumeSoftDeleted: Bool? = nil
    ) {
        self.shareID = shareID
        self.linkID = linkID
        self.volumeID = volumeID
        self.type = type
        self.state = state
        self.creationTime = creationTime
        self.modifyTime = modifyTime
        self.creator = creator
        self.flags = flags
        self.locked = locked
        self.volumeSoftDeleted = volumeSoftDeleted
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        shareID = try c.decode(String.self, forKey: .shareID)
        linkID = try c.decode(String.self, forKey: .linkID)
        volumeID = try c.decode(String.self, forKey: .volumeID)
        type = try c.decode(Int.self, forKey: .type)
        state = try c.decode(Int.self, forKey: .state)
        creationTime = try c.decode(Int64.self, forKey: .creationTime)
        modifyTime = try c.decode(Int64.self, forKey: .modifyTime)
        creator = try c.decodeIfPresent(String.self, forKey: .creator)
        flags = try c.decodeIfPresent(Int.self, forKey: .flags)
        // Live-tolerant: the Go server may encode booleans as 0/1 numbers
        // (same risk as RevisionMetadata.Thumbnail, already fixed). Accept
        // Bool, Int/Int64 (0/1), "true"/"false"/"0"/"1", null/missing → nil.
        locked = try Self.decodeBoolTolerant(c, key: .locked)
        volumeSoftDeleted = try Self.decodeBoolTolerant(c, key: .volumeSoftDeleted)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(shareID, forKey: .shareID)
        try c.encode(linkID, forKey: .linkID)
        try c.encode(volumeID, forKey: .volumeID)
        try c.encode(type, forKey: .type)
        try c.encode(state, forKey: .state)
        try c.encode(creationTime, forKey: .creationTime)
        try c.encode(modifyTime, forKey: .modifyTime)
        try c.encodeIfPresent(creator, forKey: .creator)
        try c.encodeIfPresent(flags, forKey: .flags)
        try c.encodeIfPresent(locked, forKey: .locked)
        try c.encodeIfPresent(volumeSoftDeleted, forKey: .volumeSoftDeleted)
    }

    static func decodeBoolTolerant(
        _ c: KeyedDecodingContainer<CodingKeys>, key: CodingKeys
    ) throws -> Bool? {
        if !c.contains(key) { return nil }
        if try c.decodeNil(forKey: key) { return nil }
        if let b = try? c.decode(Bool.self, forKey: key) { return b }
        if let i = try? c.decode(Int.self, forKey: key) { return i != 0 }
        if let i64 = try? c.decode(Int64.self, forKey: key) { return i64 != 0 }
        if let s = try? c.decode(String.self, forKey: key) {
            switch s.lowercased() {
            case "true", "1": return true
            case "false", "0": return false
            default:
                throw DecodingError.typeMismatch(
                    Bool.self,
                    DecodingError.Context(
                        codingPath: c.codingPath + [key],
                        debugDescription: "Expected Bool, 0/1 or \"true\"/\"false\" string"
                    )
                )
            }
        }
        throw DecodingError.typeMismatch(
            Bool.self,
            DecodingError.Context(
                codingPath: c.codingPath + [key],
                debugDescription: "Expected Bool or Int (0/1) for boolean flag"
            )
        )
    }
}

struct SharesResponse: Decodable, Sendable {
    var shares: [ShareMetadata]
    enum CodingKeys: String, CodingKey { case shares = "Shares" }
}

struct DriveShare: Decodable, Sendable {
    var shareID: String
    var linkID: String?
    var volumeID: String?
    var type: Int?
    var state: Int?
    /// Creator email address (go-proton-api Share.Creator) — used as
    /// SignatureAddress on folder/file creation.
    var creator: String?
    var addressID: String?
    var addressKeyID: String?
    var key: String?
    var passphrase: String?
    var passphraseSignature: String?

    enum CodingKeys: String, CodingKey {
        case shareID = "ShareID"
        case linkID = "LinkID"
        case volumeID = "VolumeID"
        case type = "Type"
        case state = "State"
        case creator = "Creator"
        case addressID = "AddressID"
        case addressKeyID = "AddressKeyID"
        case key = "Key"
        case passphrase = "Passphrase"
        case passphraseSignature = "PassphraseSignature"
    }
}

struct ShareResponse: Decodable, Sendable {
    var share: DriveShare
    enum CodingKeys: String, CodingKey { case share = "Share" }
}

// MARK: - Links

/// A file or folder node. Name/IDs are encrypted until F3b unlock.
struct DriveLink: Decodable, Sendable, Identifiable {
    var id: String { linkID }
    var linkID: String
    var parentLinkID: String?
    /// 1 = folder, 2 = file (go-proton-api LinkTypeFolder/File).
    var type: Int
    /// Encrypted name (armored PGP). Hash is the encrypted name HMAC.
    var name: String
    var hash: String?
    var size: Int64
    /// 0 draft, 1 active, 2 trashed, 3 deleted, 4 restoring.
    var state: Int
    var mimeType: String?
    var createTime: Int64
    var modifyTime: Int64
    var expirationTime: Int64?
    var nodeKey: String?
    var nodePassphrase: String?
    var nodePassphraseSignature: String?
    /// Address that signed the passphrase/name (go-proton-api Link.SignatureEmail).
    var signatureEmail: String?
    /// Address that signed the NAME (C# SDK Api/Links/LinkDto.cs
    /// `NameSignatureEmail`); empty → parent key signed it (anonymous).
    var nameSignatureEmail: String? = nil
    /// Extended attributes (PGP message to the node key; JSON metadata).
    var xAttr: String?
    var fileProperties: FileProperties?
    var folderProperties: FolderProperties?

    var isFolder: Bool { type == 1 }
    var isActive: Bool { state == 1 }

    enum CodingKeys: String, CodingKey {
        case linkID = "LinkID"
        case parentLinkID = "ParentLinkID"
        case type = "Type"
        case name = "Name"
        case hash = "Hash"
        case size = "Size"
        case state = "State"
        case mimeType = "MIMEType"
        case createTime = "CreateTime"
        case modifyTime = "ModifyTime"
        case expirationTime = "ExpirationTime"
        case nodeKey = "NodeKey"
        case nodePassphrase = "NodePassphrase"
        case nodePassphraseSignature = "NodePassphraseSignature"
        case signatureEmail = "SignatureEmail"
        case nameSignatureEmail = "NameSignatureEmail"
        case xAttr = "XAttr"
        case fileProperties = "FileProperties"
        case folderProperties = "FolderProperties"
    }
}

struct FileProperties: Decodable, Sendable {
    var contentKeyPacket: String?
    var contentKeyPacketSignature: String?
    var activeRevision: RevisionMetadata?

    enum CodingKeys: String, CodingKey {
        case contentKeyPacket = "ContentKeyPacket"
        case contentKeyPacketSignature = "ContentKeyPacketSignature"
        case activeRevision = "ActiveRevision"
    }
}

struct FolderProperties: Decodable, Sendable {
    var nodeHashKey: String?
    enum CodingKeys: String, CodingKey { case nodeHashKey = "NodeHashKey" }
}

struct RevisionMetadata: Codable, Sendable {
    var id: String?
    var createTime: Int64?
    var size: Int64?
    var manifestSignature: String?
    var signatureEmail: String?
    var state: Int?
    var thumbnail: Bool?
    var thumbnailHash: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case createTime = "CreateTime"
        case size = "Size"
        case manifestSignature = "ManifestSignature"
        case signatureEmail = "SignatureEmail"
        case state = "State"
        case thumbnail = "Thumbnail"
        case thumbnailHash = "ThumbnailHash"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id)
        createTime = try c.decodeIfPresent(Int64.self, forKey: .createTime)
        size = try c.decodeIfPresent(Int64.self, forKey: .size)
        manifestSignature = try c.decodeIfPresent(String.self, forKey: .manifestSignature)
        signatureEmail = try c.decodeIfPresent(String.self, forKey: .signatureEmail)
        state = try c.decodeIfPresent(Int.self, forKey: .state)
        thumbnailHash = try c.decodeIfPresent(String.self, forKey: .thumbnailHash)
        // Live-verified: committed files send Thumbnail as number (0/1);
        // drafts omit it and some paths send Bool. Accept both, encode as Bool.
        if !c.contains(.thumbnail) {
            thumbnail = nil
        } else if try c.decodeNil(forKey: .thumbnail) {
            thumbnail = nil
        } else if let b = try? c.decode(Bool.self, forKey: .thumbnail) {
            thumbnail = b
        } else if let i = try? c.decode(Int.self, forKey: .thumbnail) {
            thumbnail = i != 0
        } else if let i64 = try? c.decode(Int64.self, forKey: .thumbnail) {
            thumbnail = i64 != 0
        } else {
            throw DecodingError.typeMismatch(
                Bool.self,
                DecodingError.Context(
                    codingPath: c.codingPath + [CodingKeys.thumbnail],
                    debugDescription: "Expected Bool or Int (0/1) for Thumbnail"
                )
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(id, forKey: .id)
        try c.encodeIfPresent(createTime, forKey: .createTime)
        try c.encodeIfPresent(size, forKey: .size)
        try c.encodeIfPresent(manifestSignature, forKey: .manifestSignature)
        try c.encodeIfPresent(signatureEmail, forKey: .signatureEmail)
        try c.encodeIfPresent(state, forKey: .state)
        try c.encodeIfPresent(thumbnail, forKey: .thumbnail)
        try c.encodeIfPresent(thumbnailHash, forKey: .thumbnailHash)
    }
}

struct LinkResponse: Decodable, Sendable {
    var link: DriveLink
    enum CodingKeys: String, CodingKey { case link = "Link" }
}

struct LinksResponse: Decodable, Sendable {
    var links: [DriveLink]
    enum CodingKeys: String, CodingKey { case links = "Links" }
}

// MARK: - Folder creation (F4.2)

// POST /drive/shares/{shareID}/folders. Keys mirror go-proton-api
// CreateFolderReq (default encoding/json => capitalized field names).
struct CreateFolderRequest: Encodable, Sendable {
    var parentLinkID: String
    var name: String // encrypted to parent keyring, inline-signed by address key
    var hash: String // hex HMAC-SHA256(parentHashKey, NFC name)
    var nodeKey: String // fresh armored node key, locked with nodePassphrase
    var nodeHashKey: String // fresh random, encrypted+signed to the new node key
    var nodePassphrase: String // encrypted to parent keyring
    var nodePassphraseSignature: String // detached, signed by address key
    var signatureAddress: String? // share creator address ID (if server expects it)
    var signatureEmail: String? // signer email (Link.SignatureEmail symmetric)
    var xAttr: String? // folder/file extended attributes, encrypted to the new node key

    enum CodingKeys: String, CodingKey {
        case parentLinkID = "ParentLinkID"
        case name = "Name"
        case hash = "Hash"
        case nodeKey = "NodeKey"
        case nodeHashKey = "NodeHashKey"
        case nodePassphrase = "NodePassphrase"
        case nodePassphraseSignature = "NodePassphraseSignature"
        case signatureAddress = "SignatureAddress"
        case signatureEmail = "SignatureEmail"
        case xAttr = "XAttr"
    }

    // encodeIfPresent: Go decoding chokes on explicit nulls for plain
    // strings, and unknown/extra keys must be omitted per variant.
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(parentLinkID, forKey: .parentLinkID)
        try c.encode(name, forKey: .name)
        try c.encode(hash, forKey: .hash)
        try c.encode(nodeKey, forKey: .nodeKey)
        try c.encode(nodeHashKey, forKey: .nodeHashKey)
        try c.encode(nodePassphrase, forKey: .nodePassphrase)
        try c.encode(nodePassphraseSignature, forKey: .nodePassphraseSignature)
        try c.encodeIfPresent(signatureAddress, forKey: .signatureAddress)
        try c.encodeIfPresent(signatureEmail, forKey: .signatureEmail)
        try c.encodeIfPresent(xAttr, forKey: .xAttr)
    }
}

struct CreateFolderResponse: Decodable, Sendable {
    struct Folder: Decodable, Sendable {
        var id: String // created LinkID
        enum CodingKeys: String, CodingKey { case id = "ID" }
    }
    var folder: Folder
    enum CodingKeys: String, CodingKey { case folder = "Folder" }
}

// MARK: - File upload (F4.3)

// POST /drive/shares/{shareID}/files. Keys mirror go-proton-api
// CreateFileReq: the folder envelope (ParentLinkID, Name, Hash, NodeKey,
// NodePassphrase, NodePassphraseSignature, SignatureAddress) plus MIMEType
// and the content-key packet pair INSTEAD of NodeHashKey; NO XAttr at draft
// (XAttr is committed at revision time). Reference: /tmp/f43ref/req-4.
struct CreateFileRequest: Encodable, Sendable {
    var parentLinkID: String
    var name: String // encrypted to parent keyring, inline-signed by address key
    var hash: String // hex HMAC-SHA256(parentHashKey, NFC name)
    var mimeType: String // e.g. "text/plain; charset=utf-8"
    var contentKeyPacket: String // UNARMORED base64 of bare PKESK to node subkey
    var contentKeyPacketSignature: String // detached, self-signed by node key
    var nodeKey: String // fresh armored node key, locked with nodePassphrase
    var nodePassphrase: String // encrypted to parent keyring
    var nodePassphraseSignature: String // detached, signed by address key
    var signatureAddress: String?
    var signatureEmail: String?

    enum CodingKeys: String, CodingKey {
        case parentLinkID = "ParentLinkID"
        case name = "Name"
        case hash = "Hash"
        case mimeType = "MIMEType"
        case contentKeyPacket = "ContentKeyPacket"
        case contentKeyPacketSignature = "ContentKeyPacketSignature"
        case nodeKey = "NodeKey"
        case nodePassphrase = "NodePassphrase"
        case nodePassphraseSignature = "NodePassphraseSignature"
        case signatureAddress = "SignatureAddress"
        case signatureEmail = "SignatureEmail"
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(parentLinkID, forKey: .parentLinkID)
        try c.encode(name, forKey: .name)
        try c.encode(hash, forKey: .hash)
        try c.encode(mimeType, forKey: .mimeType)
        try c.encode(contentKeyPacket, forKey: .contentKeyPacket)
        try c.encode(contentKeyPacketSignature, forKey: .contentKeyPacketSignature)
        try c.encode(nodeKey, forKey: .nodeKey)
        try c.encode(nodePassphrase, forKey: .nodePassphrase)
        try c.encode(nodePassphraseSignature, forKey: .nodePassphraseSignature)
        try c.encodeIfPresent(signatureAddress, forKey: .signatureAddress)
        try c.encodeIfPresent(signatureEmail, forKey: .signatureEmail)
    }
}

struct CreateFileResponse: Decodable, Sendable {
    struct File: Decodable, Sendable {
        var id: String
        var revisionID: String
        enum CodingKeys: String, CodingKey {
            case id = "ID"
            case revisionID = "RevisionID"
        }
    }
    var file: File
    enum CodingKeys: String, CodingKey { case file = "File" }
}

// POST /drive/shares/{shareID}/links/{parentLinkID}/checkAvailableHashes.
// Duplicate-name probe: the server echoes free name hashes in
// AvailableHashes (PendingHashes tracks in-flight uploads).
struct CheckAvailableHashesRequest: Encodable, Sendable {
    var hashes: [String]
    enum CodingKeys: String, CodingKey { case hashes = "Hashes" }
}

struct PendingHash: Decodable, Sendable {
    /// Name-hash hex of the in-flight object.
    var hash: String?
    var revisionID: String?
    var linkID: String?
    var clientUID: String?

    enum CodingKeys: String, CodingKey {
        case hash = "Hash"
        case revisionID = "RevisionID"
        case linkID = "LinkID"
        case clientUID = "ClientUID"
    }
}

struct CheckAvailableHashesResponse: Decodable, Sendable {
    var availableHashes: [String]
    /// In-flight uploads for the probed hashes. EMPTY (`[]`) on a free name
    /// (the only shape the rclone reference `/tmp/f43ref/resp-2/3.json`
    /// captured) — but a stale draft makes the server return OBJECTS
    /// (`{Hash, RevisionID, LinkID, ClientUID:null}`, live-proven F6:
    /// a leftover state=0 draft turned the probe's hash pending and the old
    /// `[String]` model failed decode). All fields optional: this list is
    /// informational (the upload path ignores it), so shape drift must never
    /// fail the call.
    var pendingHashes: [PendingHash]
    enum CodingKeys: String, CodingKey {
        case availableHashes = "AvailableHashes"
        case pendingHashes = "PendingHashes"
    }
}

// POST /drive/blocks. One entry per block: 1-based Index, encrypted-packet
// Size, EncSignature (block-hash sig, node-encrypted), Hash (base64 SHA-256
// of the PLAINTEXT block). AddressID is the uploader's address ID.
struct BlockUploadEntry: Encodable, Sendable {
    var index: Int
    var size: Int
    var encSignature: String
    var hash: String
    enum CodingKeys: String, CodingKey {
        case index = "Index"
        case size = "Size"
        case encSignature = "EncSignature"
        case hash = "Hash"
    }
}

struct RequestBlockUploadsRequest: Encodable, Sendable {
    var addressID: String
    var shareID: String
    var linkID: String
    var revisionID: String
    var blockList: [BlockUploadEntry]
    enum CodingKeys: String, CodingKey {
        case addressID = "AddressID"
        case shareID = "ShareID"
        case linkID = "LinkID"
        case revisionID = "RevisionID"
        case blockList = "BlockList"
    }
}

struct StorageUploadLink: Decodable, Sendable {
    /// POST target (runtime storage host — never hardcode). The reference
    /// client posts to BareURL with the Token in the Pm-Storage-Token header
    /// (URL embeds the token in-path instead; either resolves server-side).
    var bareURL: String
    var token: String
    var url: String
    var index: Int
    enum CodingKeys: String, CodingKey {
        case bareURL = "BareURL"
        case token = "Token"
        case url = "URL"
        case index = "Index"
    }
}

struct RequestBlockUploadsResponse: Decodable, Sendable {
    var uploadLinks: [StorageUploadLink]
    enum CodingKeys: String, CodingKey { case uploadLinks = "UploadLinks" }
}

// PUT /drive/shares/{shareID}/files/{linkID}/revisions/{revisionID}.
struct CommitRevisionRequest: Encodable, Sendable {
    var manifestSignature: String // detached, address key over manifest input
    var signatureAddress: String?
    var signatureEmail: String?
    var xAttr: String // node-encrypted + node-signed attributes JSON
    enum CodingKeys: String, CodingKey {
        case manifestSignature = "ManifestSignature"
        case signatureAddress = "SignatureAddress"
        case signatureEmail = "SignatureEmail"
        case xAttr = "XAttr"
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(manifestSignature, forKey: .manifestSignature)
        try c.encodeIfPresent(signatureAddress, forKey: .signatureAddress)
        try c.encodeIfPresent(signatureEmail, forKey: .signatureEmail)
        try c.encode(xAttr, forKey: .xAttr)
    }
}

/// Commit response: Code envelope + a PARTIAL updated link. Fresh-commit
/// Link objects omit fields DriveLink requires (e.g. no Size yet), so the
/// link surface here is decodeIfPresent-only — use getLink for the full
/// object. (Decoding the full DriveLink here fails loudly on those shapes.)
struct CommitRevisionResponse: Decodable, Sendable {
    var code: Int
    var linkID: String?
    var state: Int?
    var size: Int64?
    enum CodingKeys: String, CodingKey {
        case code = "Code"
        case link = "Link"
    }
    enum LinkKeys: String, CodingKey {
        case linkID = "LinkID"
        case state = "State"
        case size = "Size"
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        code = try c.decode(Int.self, forKey: .code)
        if let l = try? c.nestedContainer(keyedBy: LinkKeys.self, forKey: .link) {
            linkID = try? l.decode(String.self, forKey: .linkID)
            state = try? l.decode(Int.self, forKey: .state)
            size = try? l.decodeIfPresent(Int64.self, forKey: .size)
        } else {
            linkID = nil
            state = nil
            size = nil
        }
    }
}

// MARK: - File revisions + blocks (F5 download)

// GET /drive/shares/{shareID}/files/{linkID}/revisions
// → { Revisions: [{ ID, ManifestSignature, Size, State, XAttr, … }] }.
// GET .../revisions/{revisionID}
// → { Revision: { ID, Blocks: [{ Index, Hash, Token, URL, BareURL,
// EncSignature }], ManifestSignature, Size, State, XAttr, … } }.
// Shapes captured live via rclone --dump bodies (/tmp/f5ref/): block Hash
// is base64 SHA-256 of the ENCRYPTED storage bytes (77B for the 26B
// fixture — NOT plaintext); Token is a short-lived JWT selecting the blob;
// BareURL is the runtime storage host (never hardcoded); URL embeds the
// same JWT in-path.
struct RevisionBlock: Decodable, Sendable {
    /// 1-based block index (wire `Index`).
    var index: Int
    /// base64 SHA-256 of the ENCRYPTED block bytes (verify before decrypt).
    var hash: String
    /// Short-lived storage JWT (Pm-Storage-Token header / URL path).
    var token: String
    /// Full block URL (token embedded in-path; may be empty — use BareURL).
    var url: String
    /// Runtime storage host (e.g. https://…-storage.proton.me/storage/blocks).
    var bareURL: String
    /// Armored EncSignature message (block-hash attestation; best-effort verify).
    var encSignature: String?

    enum CodingKeys: String, CodingKey {
        case index = "Index"
        case hash = "Hash"
        case token = "Token"
        case url = "URL"
        case bareURL = "BareURL"
        case encSignature = "EncSignature"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        index = try c.decode(Int.self, forKey: .index)
        hash = try c.decode(String.self, forKey: .hash)
        token = (try? c.decode(String.self, forKey: .token)) ?? ""
        url = (try? c.decode(String.self, forKey: .url)) ?? ""
        bareURL = (try? c.decode(String.self, forKey: .bareURL)) ?? ""
        encSignature = try? c.decode(String.self, forKey: .encSignature)
    }
}

/// Revision thumbnail reference. Its Hash (base64 SHA-256 of the
/// encrypted thumbnail) is PART OF THE MANIFEST, ahead of the block hashes.
/// Source: C# SDK Api/Files/ThumbnailDto.cs (`ThumbnailID`, `Type`
/// 1 = thumbnail / 2 = preview, `Hash` bytes → base64 JSON, `Size`).
struct RevisionThumbnail: Decodable, Sendable {
    var type: Int
    var hash: String

    enum CodingKeys: String, CodingKey {
        case type = "Type"
        case hash = "Hash"
    }
}

struct RevisionDetail: Decodable, Sendable {
    var id: String
    var blocks: [RevisionBlock]
    var manifestSignature: String?
    /// Address that signed the manifest (empty → node key, anonymous).
    var signatureEmail: String?
    var thumbnails: [RevisionThumbnail]
    /// Legacy single-thumbnail hash (RevisionMetadata.ThumbnailHash shape).
    var thumbnailHash: String?
    var size: Int64?
    var state: Int?
    var xAttr: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case blocks = "Blocks"
        case manifestSignature = "ManifestSignature"
        case signatureEmail = "SignatureEmail"
        case thumbnails = "Thumbnails"
        case thumbnailHash = "ThumbnailHash"
        case size = "Size"
        case state = "State"
        case xAttr = "XAttr"
    }

    init(
        id: String, blocks: [RevisionBlock], manifestSignature: String?,
        signatureEmail: String? = nil, thumbnails: [RevisionThumbnail] = [],
        thumbnailHash: String? = nil, size: Int64? = nil, state: Int? = nil, xAttr: String? = nil
    ) {
        self.id = id
        self.blocks = blocks
        self.manifestSignature = manifestSignature
        self.signatureEmail = signatureEmail
        self.thumbnails = thumbnails
        self.thumbnailHash = thumbnailHash
        self.size = size
        self.state = state
        self.xAttr = xAttr
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? ""
        blocks = (try? c.decode([RevisionBlock].self, forKey: .blocks)) ?? []
        manifestSignature = try? c.decode(String.self, forKey: .manifestSignature)
        signatureEmail = try? c.decode(String.self, forKey: .signatureEmail)
        thumbnails = (try? c.decode([RevisionThumbnail].self, forKey: .thumbnails)) ?? []
        thumbnailHash = try? c.decode(String.self, forKey: .thumbnailHash)
        size = try? c.decode(Int64.self, forKey: .size)
        state = try? c.decode(Int.self, forKey: .state)
        xAttr = try? c.decode(String.self, forKey: .xAttr)
    }
}

struct RevisionSummary: Decodable, Sendable {
    var id: String
    var manifestSignature: String?
    var size: Int64?
    var state: Int?
    var xAttr: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID"
        case manifestSignature = "ManifestSignature"
        case size = "Size"
        case state = "State"
        case xAttr = "XAttr"
    }
}

struct RevisionsResponse: Decodable, Sendable {
    var revisions: [RevisionSummary]
    enum CodingKeys: String, CodingKey { case revisions = "Revisions" }
}

struct RevisionResponse: Decodable, Sendable {
    var revision: RevisionDetail
    enum CodingKeys: String, CodingKey { case revision = "Revision" }
}

// MARK: - Batch trash / delete (cleanup)

// POST /drive/shares/{shareID}/folders/{parentLinkID}/{trash_multiple,delete_multiple}.
struct BatchChildrenRequest: Encodable, Sendable {
    var linkIDs: [String]
    enum CodingKeys: String, CodingKey { case linkIDs = "LinkIDs" }
}

struct BatchChildStatus: Decodable, Sendable {
    var code: Int
    var error: String?
    enum CodingKeys: String, CodingKey {
        case code = "Code"
        case error = "Error"
    }
}

struct BatchChildResult: Decodable, Sendable {
    var linkID: String
    var response: BatchChildStatus
    enum CodingKeys: String, CodingKey {
        case linkID = "LinkID"
        case response = "Response"
    }
}

struct BatchChildrenResponse: Decodable, Sendable {
    var responses: [BatchChildResult]
    enum CodingKeys: String, CodingKey { case responses = "Responses" }
}
