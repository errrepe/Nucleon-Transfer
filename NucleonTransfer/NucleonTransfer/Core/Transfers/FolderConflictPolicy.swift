// Nucleon Transfer — duplicate-name conflict policy for uploads (F7.1 R4).
// Pure, testable decision layer for "the server says this folder name
// already exists": isDuplicateName recognizes the API answer, resolve()
// picks merge-vs-fail given the parent's decrypted children. The single
// source of truth for code 2500 — FolderOperations maps the same error
// through it instead of keeping a second copy.

import Foundation

/// What to do after a createFolder call answered "name already exists".
enum FolderConflictResolution: Equatable, Sendable {
    /// An existing FOLDER holds the name — merge into it (reuse its LinkID).
    case reuse(linkID: String)
    /// The name is taken by a FILE, or no matching child could be found —
    /// surface the reason and stop.
    case fail(message: String)
}

enum FolderConflictPolicy {
    /// Is this API error the "same name already exists" answer? Code 2500
    /// (AlreadyExists → NodeWithSameNameExists, ProtonDriveApps/sdk
    /// DriveApiResponseCodes) plus a belt-and-braces text fallback in case
    /// a variant deployment answers differently.
    static func isDuplicateName(_ error: Error) -> Bool {
        guard let api = error as? ProtonAPIError,
              case let .api(code, message) = api
        else { return false }
        return code == 2500 || message.localizedCaseInsensitiveContains("exist")
    }

    /// Picks what to do once a duplicate was reported, given the parent's
    /// decrypted children. Exact match after NFC normalization — the server
    /// compares name hashes, so the match is exact and case-sensitive.
    /// Children whose names never decrypted ("Encrypted Item") can't be
    /// confirmed as the conflicting node and never match.
    static func resolve(name: String, children: [DriveItem]) -> FolderConflictResolution {
        let target = name.precomposedStringWithCanonicalMapping
        for child in children
        where child.isNameDecrypted
            && child.name.precomposedStringWithCanonicalMapping == target
        {
            if child.isFolder {
                return .reuse(linkID: child.id)
            }
            return .fail(
                message: String(localized: "A file named “\(name)” already exists here, so the folder can’t be created.")
            )
        }
        // The server reported a duplicate but the listing shows no matching
        // name (decrypt failure, or a trashed/draft node holding the hash).
        return .fail(
            message: String(localized: "“\(name)” already exists but the conflicting item couldn’t be identified — reload the folder and retry.")
        )
    }
}
