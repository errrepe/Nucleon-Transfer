// Nucleon Transfer — New Folder sheet (F7 S2.3 / F7.1 R5).
// Small modal: name field (starts as "Untitled Folder", fully selected so
// typing replaces it), inline validation/creation errors in red, and
// Cancel / Create buttons — Create is the default action, disabled while
// the name is invalid, and swaps to a spinner while the request is in
// flight. R5 adds live duplicate detection: the decrypted names already
// in the folder come in as `existingNames` and fail validation before any
// request goes out. Errors stay inline (the sheet remains open so the
// name can be fixed); only a successful create dismisses.
import AppKit // NSApp.sendAction(selectAll:) — preselects the default name
import SwiftUI

struct NewFolderSheet: View {
    /// Creates the folder; throws a user-mappable error on failure
    /// (duplicate name, network, session). The parent supplies
    /// BrowserModel.createFolder(named:).
    var onCreate: (String) async throws -> Void
    /// Decrypted names already present in the target folder — checked
    /// live, so a duplicate disables Create before the API call (R5).
    /// NFC-exact, case-sensitive (FolderNameValidator).
    let existingNames: Set<String>

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var error: String?
    @State private var edited = false
    @State private var isCreating = false
    @FocusState private var nameFocused: Bool

    init(
        initialName: String = String(localized: "Untitled Folder", comment: "Default name of a new folder"),
        existingNames: Set<String> = [],
        initialError: String? = nil,
        initiallyEdited: Bool = false,
        onCreate: @escaping (String) async throws -> Void
    ) {
        _name = State(initialValue: initialName)
        _error = State(initialValue: initialError)
        _edited = State(initialValue: initiallyEdited)
        self.existingNames = existingNames
        self.onCreate = onCreate
    }

    private var validation: Result<String, FolderNameError> {
        FolderNameValidator.validate(name, existingNames: existingNames)
    }

    /// Validation errors show once the field was touched or Create was
    /// attempted; a thrown create error always shows.
    private var inlineError: String? {
        if let error { return error }
        guard edited else { return nil }
        if case let .failure(failure) = validation { return failure.message }
        return nil
    }

    private var isValid: Bool {
        if case .success = validation { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Folder")
                .font(.headline)
            // A1: the label doubles as the AX label; the visible hint is
            // a prompt, so an empty field exposes an EMPTY AX value —
            // not the placeholder text read as content (QA A-level).
            TextField("Name", text: $name, prompt: Text("Folder name"))
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                .focused($nameFocused)
                .disabled(isCreating)
                .onChange(of: name) { _, _ in
                    edited = true
                    error = nil // typing clears a stale server error
                }
                .accessibilityLabel("Folder name")
            if let inlineError {
                Text(inlineError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                if isCreating {
                    ProgressView()
                        .controlSize(.small)
                }
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isCreating)
                Button("Create") { Task { await create() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isValid || isCreating)
            }
        }
        .padding(20)
        .frame(width: 340)
        .task {
            nameFocused = true
            // Select the default name so typing replaces it outright —
            // same UX as Finder's New Folder.
            NSApp.sendAction(#selector(NSResponder.selectAll(_:)), to: nil, from: nil)
        }
    }

    private func create() async {
        guard case let .success(validName) = validation else {
            edited = true
            return
        }
        isCreating = true
        defer { isCreating = false }
        do {
            try await onCreate(validName)
            dismiss()
        } catch {
            self.error = UserFacingError.message(for: error)
        }
    }
}

#if DEBUG
#Preview("Normal — Light") {
    NewFolderSheet { _ in }
        .preferredColorScheme(.light)
}

#Preview("Normal — Dark") {
    NewFolderSheet { _ in }
        .preferredColorScheme(.dark)
}

// R6/A1: field emptied by the user — the "Folder name" prompt shows in
// place of content (the prompt is the placeholder, not the AX value).
#Preview("Empty Field — Dark") {
    NewFolderSheet(initialName: "") { _ in }
        .preferredColorScheme(.dark)
}

#Preview("Duplicate Error — Light") {
    NewFolderSheet(
        initialName: "Invoices",
        initialError: "A folder named “Invoices” already exists."
    ) { _ in }
    .preferredColorScheme(.light)
}

#Preview("Duplicate Error — Dark") {
    NewFolderSheet(
        initialName: "Invoices",
        initialError: "A folder named “Invoices” already exists."
    ) { _ in }
    .preferredColorScheme(.dark)
}

// R5: the duplicate caught client-side — no request was sent. The error
// comes from validation (not a thrown create), so `initiallyEdited`
// simulates the field having been touched.
#Preview("Duplicate (live validation) — Light") {
    NewFolderSheet(
        initialName: "Invoices",
        existingNames: ["Invoices", "report.pdf"],
        initiallyEdited: true
    ) { _ in }
    .preferredColorScheme(.light)
}

#Preview("Duplicate (live validation) — Dark") {
    NewFolderSheet(
        initialName: "Invoices",
        existingNames: ["Invoices", "report.pdf"],
        initiallyEdited: true
    ) { _ in }
    .preferredColorScheme(.dark)
}
#endif
