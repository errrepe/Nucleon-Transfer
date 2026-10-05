// Nucleon Transfer — new-folder name validation (F7 S2.3 / F7.1 R5).
// Pure value checks for the New Folder sheet + FolderOperations: the rules
// mirror what Proton Drive clients enforce before hitting the API (the
// server answers duplicates with 2500/AlreadyExists, but bad names should
// never leave the client — and R5 flags a same-folder duplicate before
// the request even goes out). NFC output: Drive name hashes are computed
// over the NFC form (FolderCreate.buildRequest applies the same
// normalization).
import Foundation

enum FolderNameError: Error, Equatable, Sendable {
    case empty
    case invalidCharacters    // "/" or NUL
    case reserved             // "." or ".."
    case tooLong              // > 255 UTF-8 bytes
    case alreadyExists(String) // sibling folder OR file holds the name

    /// Short inline message for the New Folder sheet (sentence case).
    var message: String {
        switch self {
        case .empty:
            return String(localized: "Enter a folder name.")
        case .invalidCharacters:
            return String(localized: "Folder names can’t contain “/”.")
        case .reserved:
            return String(localized: "“.” and “..” are reserved names.")
        case .tooLong:
            // M6: the limit is 255 UTF-8 BYTES — a char count would be a
            // lie for accented names/emoji, so the copy stays unit-free.
            return String(localized: "That name is too long. Try a shorter name.")
        case .alreadyExists(let name):
            return String(localized: "A folder or file named “\(name)” already exists here.")
        }
    }
}

enum FolderNameValidator {
    /// Trim → reject empty / "/" or NUL / "." and ".." / >255 UTF-8 bytes;
    /// on success returns the NFC-normalized name (what the API stores and
    /// hashes). Never throws — validation is total.
    static func validate(_ raw: String) -> Result<String, FolderNameError> {
        validate(raw, existingNames: [])
    }

    /// Same checks plus a duplicate test against the names already present
    /// in the target folder (folders AND files — the server rejects either
    /// collision with 2500). The match is NFC-exact and case-sensitive,
    /// the same rule FolderConflictPolicy.resolve applies to the server's
    /// answer, because Drive hashes the NFC form of the name.
    static func validate(
        _ raw: String,
        existingNames: Set<String>
    ) -> Result<String, FolderNameError> {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .precomposedStringWithCanonicalMapping
        if name.isEmpty { return .failure(.empty) }
        if name.contains("/") || name.contains("\0") { return .failure(.invalidCharacters) }
        if name == "." || name == ".." { return .failure(.reserved) }
        if name.utf8.count > 255 { return .failure(.tooLong) }
        // Both sides normalized to NFC so a decomposed listing name still
        // matches; checked last so a malformed name keeps reporting its
        // real error instead of "already exists".
        let existing = Set(existingNames.map { $0.precomposedStringWithCanonicalMapping })
        if existing.contains(name) { return .failure(.alreadyExists(name)) }
        return .success(name)
    }
}
