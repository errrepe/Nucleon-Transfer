// Nucleon Transfer — F8.4-U7b settings wiring (Swift Testing).
// BoundedConcurrency (the "Simultaneous downloads" pacer: width bound,
// in-order starts, stop-starting gate) and the typed Proton 2000 row text.
// Pure Core, no network.
import Foundation
import Synchronization
import Testing

@testable import NucleonTransfer

/// Records how many bodies run at once and the order they start in.
private final class ConcurrencyProbe: Sendable {
    struct State {
        var running = 0
        var maxRunning = 0
        var started: [Int] = []
    }

    let state = Mutex(State())

    func run(_ element: Int) async {
        state.withLock {
            $0.running += 1
            $0.maxRunning = max($0.maxRunning, $0.running)
            $0.started.append(element)
        }
        try? await Task.sleep(for: .milliseconds(5))
        state.withLock { $0.running -= 1 }
    }
}

struct BoundedConcurrencyTests {
    @Test func neverExceedsWidthAndRunsEveryElement() async {
        let probe = ConcurrencyProbe()
        await BoundedConcurrency.forEach(Array(0..<12), width: 3) { await probe.run($0) }
        let state = probe.state.withLock { $0 }
        #expect(state.maxRunning <= 3)
        #expect(state.maxRunning > 1) // actually parallel
        #expect(state.started.sorted() == Array(0..<12))
        #expect(state.running == 0) // returns only after every body finished
    }

    @Test func widthOneIsSequentialAndInOrder() async {
        let probe = ConcurrencyProbe()
        await BoundedConcurrency.forEach(Array(0..<5), width: 1) { await probe.run($0) }
        let state = probe.state.withLock { $0 }
        #expect(state.maxRunning == 1)
        #expect(state.started == Array(0..<5))
    }

    @Test func nonPositiveWidthFallsBackToOne() async {
        let probe = ConcurrencyProbe()
        await BoundedConcurrency.forEach(Array(0..<4), width: 0) { await probe.run($0) }
        let state = probe.state.withLock { $0 }
        #expect(state.maxRunning == 1)
        #expect(state.started.count == 4)
    }

    /// The batch-epoch gate: once `shouldStart` says no, nothing new
    /// starts (cancelAll), but bodies already running finish.
    @Test func stopsStartingWhenGateCloses() async {
        let probe = ConcurrencyProbe()
        var allowed = 3
        await BoundedConcurrency.forEach(
            Array(0..<10), width: 2,
            shouldStart: {
                defer { allowed -= 1 }
                return allowed > 0
            }
        ) { await probe.run($0) }
        let state = probe.state.withLock { $0 }
        #expect(state.started.sorted() == [0, 1, 2])
        #expect(state.running == 0)
    }

    /// Review fix (F8.4): two download batches running at once share one
    /// "Simultaneous downloads" width instead of each getting their own.
    @Test func sharedSlotsBoundConcurrentRunsTogether() async {
        let probe = ConcurrencyProbe()
        let slots = AsyncSlots()
        async let first: Void = BoundedConcurrency.forEach(
            Array(0..<6), slots: slots, width: 2
        ) { await probe.run($0) }
        async let second: Void = BoundedConcurrency.forEach(
            Array(100..<106), slots: slots, width: 2
        ) { await probe.run($0) }
        _ = await (first, second)
        let state = probe.state.withLock { $0 }
        #expect(state.maxRunning <= 2)
        #expect(state.started.count == 12)
        #expect(state.running == 0)
        #expect(await slots.inUse == 0) // every slot handed back
    }

    /// A closed gate hands its granted slot back, so the other run goes on.
    @Test func closedGateReleasesItsSlot() async {
        let probe = ConcurrencyProbe()
        let slots = AsyncSlots()
        await BoundedConcurrency.forEach(
            Array(0..<4), slots: slots, width: 1, shouldStart: { false }
        ) { await probe.run($0) }
        #expect(await slots.inUse == 0)
        await BoundedConcurrency.forEach(Array(0..<3), slots: slots, width: 1) { await probe.run($0) }
        #expect(probe.state.withLock { $0.started } == [0, 1, 2])
    }

    @Test func emptyInputReturnsImmediately() async {
        let probe = ConcurrencyProbe()
        await BoundedConcurrency.forEach([Int](), width: 4) { await probe.run($0) }
        #expect(probe.state.withLock { $0.started }.isEmpty)
    }
}

struct UploadAllowlistRowTextTests {
    private func failed(code: Int?, message: String?) -> TransferJob {
        var job = makeJob()
        job.state = .failed
        job.errorCode = code
        job.errorMessage = message
        return job
    }

    /// Typed code wins even when the stored text wouldn't match (e.g. an
    /// already user-facing message from Proton's envelope).
    @Test func typedCodeGivesShortText() {
        let job = failed(code: UploadBlockDetection.notAllowlistedCode,
                         message: "You are using an outdated version of the app.")
        #expect(UserFacingError.message(forJob: job) == UserFacingError.uploadAllowlisted)
        #expect(TransferDisplay.item(for: job, destinationName: nil).subtitle
            == "Upload not available yet (Error 2000).")
    }

    /// Jobs persisted before `errorCode` existed keep the string fallback.
    @Test func legacyJobFallsBackToMessageToken() {
        let job = failed(code: nil, message: "api 2000: You are using an outdated version of the app.")
        #expect(UserFacingError.message(forJob: job) == UserFacingError.uploadAllowlisted)
    }

    @Test func otherCodesUseTheMessage() {
        let job = failed(code: 2500, message: "api 2500: exists")
        #expect(UserFacingError.message(forJob: job)
            == "An item with this name already exists here. Rename it and try again. (Error 2500)")
        let missing = failed(code: nil, message: nil)
        #expect(UserFacingError.message(forJob: missing) == "Upload failed")
    }
}
