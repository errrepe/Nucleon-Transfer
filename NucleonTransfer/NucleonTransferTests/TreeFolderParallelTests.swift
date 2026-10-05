// Nucleon Transfer — F8.3-P4 parallel folder creation in enqueueTree
// (Swift Testing). A delayed folder fake records concurrency and the order
// in which parents become available.
import Foundation
import Synchronization
import Testing

@testable import NucleonTransfer

/// Folder fake: deterministic LinkIDs ("parent/name"), optional delay and
/// failing names; records concurrency and parent-before-child violations.
private final class DelayedFolders: RemoteFolderCreator {
    struct State {
        var concurrent = 0
        var maxConcurrent = 0
        var calls: [(name: String, parent: String)] = []
        /// LinkIDs whose ensureFolder has returned.
        var finished: Set<String> = []
        /// Calls whose parent had not finished yet when they started.
        var orphanStarts: [String] = []
    }

    let root: String
    let delayNanoseconds: UInt64
    let failing: Set<String>
    let state = Mutex(State())

    init(root: String, delayNanoseconds: UInt64 = 0, failing: Set<String> = []) {
        self.root = root
        self.delayNanoseconds = delayNanoseconds
        self.failing = failing
    }

    func ensureFolder(name: String, parentLinkID: String, shareID: String) async throws -> String {
        state.withLock {
            $0.concurrent += 1
            $0.maxConcurrent = max($0.maxConcurrent, $0.concurrent)
            $0.calls.append((name, parentLinkID))
            if parentLinkID != root, !$0.finished.contains(parentLinkID) {
                $0.orphanStarts.append(name)
            }
        }
        defer { state.withLock { $0.concurrent -= 1 } }
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if failing.contains(name) { throw TransferFailure.permanent("fail \(name)") }
        let id = "\(parentLinkID)/\(name)"
        state.withLock { _ = $0.finished.insert(id) }
        return id
    }
}

private func dir(_ rel: String) -> LocalTreeScan.Entry {
    LocalTreeScan.Entry(url: URL(fileURLWithPath: "/drop/\(rel)"), relativePath: rel, isDirectory: true, size: 0)
}

private func file(_ rel: String) -> LocalTreeScan.Entry {
    LocalTreeScan.Entry(url: URL(fileURLWithPath: "/drop/\(rel)"), relativePath: rel, isDirectory: false, size: 1)
}

/// `fanout` = children per folder at each level; one file per folder.
private func tree(fanout: [Int]) -> [LocalTreeScan.Entry] {
    var entries = [dir("")]
    var level = [""]
    for width in fanout {
        var next: [String] = []
        for parent in level {
            for i in 0..<width {
                let rel = parent.isEmpty ? "d\(i)" : "\(parent)/d\(i)"
                entries.append(dir(rel))
                entries.append(file("\(rel)/f.txt"))
                next.append(rel)
            }
        }
        level = next
    }
    return entries
}

private func run(
    _ entries: [LocalTreeScan.Entry], folders: DelayedFolders, width: Int
) async throws -> [String: String] {
    let (q, _) = await makeQueue()
    try await q.enqueueTree(
        entries: entries, shareID: "S", rootParentLinkID: folders.root,
        folders: folders, folderConcurrency: width
    )
    return Dictionary(uniqueKeysWithValues: await q.snapshot().map { ($0.relativePath, $0.parentLinkID) })
}

struct TreeFolderParallelTests {
    @Test func wideLevelRunsInParallelButBounded() async throws {
        let folders = DelayedFolders(root: "ROOT", delayNanoseconds: 5_000_000)
        _ = try await run(tree(fanout: [12, 2]), folders: folders, width: 4)
        let s = folders.state.withLock { $0 }
        #expect(s.calls.count == 12 + 24)
        #expect(s.maxConcurrent > 1)
        #expect(s.maxConcurrent <= 4)
    }

    @Test func everyParentExistsBeforeItsChildStarts() async throws {
        let folders = DelayedFolders(root: "ROOT", delayNanoseconds: 1_000_000)
        _ = try await run(tree(fanout: [3, 3, 3]), folders: folders, width: 4)
        let s = folders.state.withLock { $0 }
        #expect(s.calls.count == 3 + 9 + 27)
        #expect(s.orphanStarts.isEmpty)
    }

    @Test func parallelMapMatchesSequential() async throws {
        let entries = tree(fanout: [4, 3, 2])
        let sequential = try await run(entries, folders: DelayedFolders(root: "ROOT"), width: 1)
        let parallel = try await run(entries, folders: DelayedFolders(root: "ROOT", delayNanoseconds: 500_000), width: 4)
        #expect(sequential.count == 4 + 12 + 24)
        #expect(parallel == sequential)
        #expect(parallel["d1/d2/d0/f.txt"] == "ROOT/d1/d2/d0")
    }

    @Test func failureAbortsTheEnqueueAndStopsDeeperLevels() async throws {
        let folders = DelayedFolders(root: "ROOT", delayNanoseconds: 1_000_000, failing: ["d2"])
        let (q, _) = await makeQueue()
        await #expect(throws: TransferFailure.permanent("fail d2")) {
            try await q.enqueueTree(
                entries: tree(fanout: [3, 3, 3]), shareID: "S", rootParentLinkID: "ROOT", folders: folders
            )
        }
        #expect(await q.snapshot().isEmpty) // nothing enqueued, like the sequential path
        // "d2" fails at depth 1 → depth 2 never starts.
        let parents = folders.state.withLock { $0.calls.map(\.parent) }
        #expect(parents.allSatisfy { $0 == "ROOT" })
    }

    @Test func lowestFailingPathWinsRegardlessOfCompletionOrder() async throws {
        // Both top-level folders fail; "a" sorts first, so its error is thrown.
        let entries = [dir(""), dir("a"), dir("b"), file("a/x.txt")]
        let folders = DelayedFolders(root: "ROOT", failing: ["a", "b"])
        let (q, _) = await makeQueue()
        await #expect(throws: TransferFailure.permanent("fail a")) {
            try await q.enqueueTree(entries: entries, shareID: "S", rootParentLinkID: "ROOT", folders: folders)
        }
    }

    @Test func samePathTwiceAndSameNormalizedNameShareOneCreate() async throws {
        // NFD vs NFC spellings of one name under one parent: one create
        // (concurrent creates would race the merge policy).
        let nfd = "Fe\u{0301}rias", nfc = "F\u{00E9}rias"
        let entries = [dir(nfd), dir(nfc), dir(nfc), file("\(nfd)/a.txt"), file("\(nfc)/b.txt")]
        let folders = DelayedFolders(root: "ROOT")
        let byRel = try await run(entries, folders: folders, width: 4)
        #expect(folders.state.withLock { $0.calls.count } == 1)
        #expect(byRel["\(nfd)/a.txt"] == "ROOT/\(nfc)")
        #expect(byRel["\(nfc)/b.txt"] == "ROOT/\(nfc)")
    }

    /// Measurement for the slice report: 100 folders over 3 levels
    /// (4 → 24 → 72), 20 ms per fake create; sequential (width 1, the old
    /// one-at-a-time behaviour) vs. width 4.
    @Test func timing100FoldersAcross3Levels() async throws {
        let entries = tree(fanout: [4, 6, 3])
        #expect(entries.filter { $0.isDirectory && !$0.relativePath.isEmpty }.count == 100)
        func time(width: Int) async throws -> Double {
            let start = ContinuousClock.now
            _ = try await run(entries, folders: DelayedFolders(root: "ROOT", delayNanoseconds: 20_000_000), width: width)
            let d = ContinuousClock.now - start
            return Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
        }
        let sequential = try await time(width: 1)
        let parallel = try await time(width: 4)
        print("F8.3-P4 timing: 100 folders x 20 ms — sequential \(Int(sequential * 1000)) ms, width 4 \(Int(parallel * 1000)) ms")
        #expect(parallel < sequential / 2)
    }
}
