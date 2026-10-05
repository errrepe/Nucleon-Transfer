// Nucleon Transfer — F8.2-R7 folder listing ordering (Swift Testing).
// Latest request wins per folder; optimistic trash removals stay hidden
// from listings that predate the server-side removal. Pure value type.
import Foundation
import Testing

@testable import NucleonTransfer

private func row(_ id: String) -> DriveItem {
    DriveItem(
        id: id, shareID: "S", parentLinkID: "P", name: id,
        isNameDecrypted: true, kind: .file, size: 1,
        modified: Date(timeIntervalSince1970: 1_700_000_000), mimeType: nil
    )
}

private func ids(_ items: [DriveItem]?) -> [String]? { items?.map(\.id) }

struct FolderLoadGateTests {
    @Test func olderRequestFinishingLastIsDropped() {
        var gate = FolderLoadGate()
        let old = gate.begin(folder: "F")
        let new = gate.begin(folder: "F")
        #expect(ids(gate.apply([row("a"), row("b")], token: new, folder: "F")) == ["a", "b"])
        #expect(gate.apply([row("a")], token: old, folder: "F") == nil)
        #expect(!gate.isCurrent(old, folder: "F"))
        #expect(gate.isCurrent(new, folder: "F"))
    }

    @Test func olderRequestFinishingFirstIsDroppedToo() {
        var gate = FolderLoadGate()
        let old = gate.begin(folder: "F")
        let new = gate.begin(folder: "F")
        #expect(gate.apply([row("stale")], token: old, folder: "F") == nil)
        #expect(ids(gate.apply([row("fresh")], token: new, folder: "F")) == ["fresh"])
    }

    @Test func foldersAreIndependent() {
        var gate = FolderLoadGate()
        let a = gate.begin(folder: "A")
        let b = gate.begin(folder: "B")
        #expect(ids(gate.apply([row("x")], token: a, folder: "A")) == ["x"])
        #expect(ids(gate.apply([row("y")], token: b, folder: "B")) == ["y"])
    }

    @Test func listingRequestedBeforeTrashCannotResurrectRows() {
        var gate = FolderLoadGate()
        let inFlight = gate.begin(folder: "F")
        let handle = gate.beginRemoval(["b"], folder: "F")
        // Still running: hidden.
        #expect(ids(gate.apply([row("a"), row("b")], token: inFlight, folder: "F")) == ["a"])
        // Requested before the trash landed, applied after: still hidden.
        let racing = gate.begin(folder: "F")
        gate.finishRemoval(handle, folder: "F", succeeded: true)
        #expect(ids(gate.apply([row("a"), row("b")], token: racing, folder: "F")) == ["a"])
    }

    @Test func listingAfterSuccessfulTrashIsUnfilteredAndRetiresIt() {
        var gate = FolderLoadGate()
        let handle = gate.beginRemoval(["b"], folder: "F")
        gate.finishRemoval(handle, folder: "F", succeeded: true)
        let fresh = gate.begin(folder: "F")
        // The server is the truth for listings requested after the trash
        // (a same-ID row here would be a real server row).
        #expect(ids(gate.apply([row("a"), row("b")], token: fresh, folder: "F")) == ["a", "b"])
        let later = gate.begin(folder: "F")
        #expect(ids(gate.apply([row("a"), row("b")], token: later, folder: "F")) == ["a", "b"])
    }

    @Test func failedTrashStopsHidingRows() {
        var gate = FolderLoadGate()
        let handle = gate.beginRemoval(["b"], folder: "F")
        gate.finishRemoval(handle, folder: "F", succeeded: false)
        let reload = gate.begin(folder: "F")
        #expect(ids(gate.apply([row("a"), row("b")], token: reload, folder: "F")) == ["a", "b"])
    }

    @Test func removalInOtherFolderDoesNotFilter() {
        var gate = FolderLoadGate()
        _ = gate.beginRemoval(["b"], folder: "G")
        let token = gate.begin(folder: "F")
        #expect(ids(gate.apply([row("a"), row("b")], token: token, folder: "F")) == ["a", "b"])
    }
}
