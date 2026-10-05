// Nucleon Transfer — folder name-conflict policy suite (F7.1 R4, Swift
// Testing). Pure value-type inputs (DriveItem rows, ProtonAPIError) — no
// network, no keys, no actors.
import Foundation
import Testing

@testable import NucleonTransfer

private func child(
    _ id: String, name: String, folder: Bool, decrypted: Bool = true
) -> DriveItem {
    DriveItem(
        id: id, shareID: "S", parentLinkID: "P",
        name: decrypted ? name : "Encrypted Item",
        isNameDecrypted: decrypted,
        kind: folder ? .folder : .file,
        size: folder ? 0 : 12,
        modified: Date(timeIntervalSince1970: 1_700_000_000),
        mimeType: nil
    )
}

struct FolderConflictPolicyTests {
    // MARK: isDuplicateName

    @Test func code2500IsDuplicate() {
        let error = ProtonAPIError.api(code: 2500, message: "whatever")
        #expect(FolderConflictPolicy.isDuplicateName(error))
    }

    @Test func otherCodeIsNotDuplicate() {
        let error = ProtonAPIError.api(code: 2511, message: "invalid share type")
        #expect(!FolderConflictPolicy.isDuplicateName(error))
    }

    @Test func alreadyExistsTextIsDuplicate() {
        // Variant-deployment fallback: unknown code, "exist" in the text.
        let error = ProtonAPIError.api(
            code: 9000, message: "A node with this name already exists"
        )
        #expect(FolderConflictPolicy.isDuplicateName(error))
    }

    @Test func nonAPIErrorsAreNotDuplicate() {
        #expect(!FolderConflictPolicy.isDuplicateName(
            ProtonAPIError.api(code: 404, message: "not found")
        ))
        #expect(!FolderConflictPolicy.isDuplicateName(
            ProtonAPIError.unauthorized
        ))
        #expect(!FolderConflictPolicy.isDuplicateName(
            ProtonAPIError.transport(URLError(.timedOut))
        ))
        #expect(!FolderConflictPolicy.isDuplicateName(
            URLError(.notConnectedToInternet)
        ))
    }

    // MARK: resolve

    @Test func resolveFindsFolderWithSameName() {
        let children = [
            child("L-other", name: "Other", folder: true),
            child("L-docs", name: "Docs", folder: true),
        ]
        #expect(
            FolderConflictPolicy.resolve(name: "Docs", children: children)
                == .reuse(linkID: "L-docs")
        )
    }

    @Test func resolveMatchesAcrossNFCForms() {
        // Server hashes the NFC name — "ação" composed vs decomposed is the
        // same remote name and must match.
        let composed = "a\u{00E7}\u{00E3}o" // a + ç + ã + o (NFC)
        let decomposed = "ac\u{0327}a\u{0303}o" // a + c+cedilla + a+tilde + o (NFD)
        let children = [child("L-acao", name: decomposed, folder: true)]
        #expect(
            FolderConflictPolicy.resolve(name: composed, children: children)
                == .reuse(linkID: "L-acao")
        )
    }

    @Test func resolveIsCaseSensitive() {
        // Hash match is exact: "Docs" existing does NOT make "docs" a
        // duplicate — no child matches, so resolve fails.
        let children = [child("L-docs", name: "Docs", folder: true)]
        let result = FolderConflictPolicy.resolve(name: "docs", children: children)
        guard case .fail = result else {
            Issue.record("expected .fail for a case-mismatched name, got \(result)")
            return
        }
    }

    @Test func resolveFailsWhenNameIsTakenByFile() {
        let children = [child("L-file", name: "Docs", folder: false)]
        let result = FolderConflictPolicy.resolve(name: "Docs", children: children)
        #expect(result == .fail(message: "copy folder-name-taken-by-file"))
        // Name-free token; the localized copy appears only on display.
        guard case let .fail(message) = result else { return }
        #expect(!message.contains("Docs"))
        #expect(UserFacingError.message(for: TransferFailure.permanent(message))
            == UserFacingError.Copy.folderNameTakenByFile.text)
    }

    @Test func resolveFailsWithNoMatch() {
        let children = [
            child("L-a", name: "Alpha", folder: true),
            child("L-b", name: "Beta", folder: false),
        ]
        let result = FolderConflictPolicy.resolve(name: "Gamma", children: children)
        #expect(result == .fail(message: "copy folder-conflict-unidentified"))
        guard case .fail = result else {
            Issue.record("expected .fail when no child matches, got \(result)")
            return
        }
    }

    @Test func resolveIgnoresUndecryptedNames() {
        // An "Encrypted Item" can't be confirmed as the conflicting node —
        // never merge into an unverified folder.
        let children = [child("L-mystery", name: "whatever", folder: true, decrypted: false)]
        let result = FolderConflictPolicy.resolve(
            name: "Encrypted Item", children: children
        )
        guard case .fail = result else {
            Issue.record("expected .fail for an undecrypted name, got \(result)")
            return
        }
    }
}
