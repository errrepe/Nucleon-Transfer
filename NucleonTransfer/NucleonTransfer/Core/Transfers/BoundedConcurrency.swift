// Nucleon Transfer — bounded parallel for-each (F8.4-U7b; F8.4 review:
// shared slots).
// Runs one async body per element with at most `width` in flight, starting
// elements in order. `shouldStart` is consulted (on the caller's isolation)
// right before each start: once it answers false nothing new starts, and
// the call returns after the running bodies finish. Used by
// DownloadCoordinator for "Simultaneous downloads" — the per-item Task,
// record and cancellation stay with the caller; this only paces starts.
// Several runs can share one `AsyncSlots`: the width then bounds them all
// together (two download batches never exceed the setting combined), and
// waiting starts are served first come, first served across runs.

import Foundation

enum BoundedConcurrency {
    /// `width` below 1 is treated as 1 (sequential). Private slots: this
    /// run is bounded on its own.
    static func forEach<Element: Sendable>(
        _ elements: [Element],
        width: Int,
        isolation: isolated (any Actor)? = #isolation,
        shouldStart: () -> Bool = { true },
        _ body: @escaping @Sendable (Element) async -> Void
    ) async {
        await forEach(
            elements, slots: AsyncSlots(), width: width,
            shouldStart: shouldStart, body
        )
    }

    /// Same, drawing from `slots` shared with other runs: an element starts
    /// once fewer than `width` bodies (of every run on `slots`) are in
    /// flight. A run waiting for a slot does not observe Task cancellation;
    /// callers stop it through `shouldStart`, which is checked after each
    /// slot is granted.
    static func forEach<Element: Sendable>(
        _ elements: [Element],
        slots: AsyncSlots,
        width: Int,
        isolation: isolated (any Actor)? = #isolation,
        shouldStart: () -> Bool = { true },
        _ body: @escaping @Sendable (Element) async -> Void
    ) async {
        await withDiscardingTaskGroup { group in
            for element in elements {
                await slots.acquire(limit: width)
                guard shouldStart() else {
                    await slots.release()
                    break // stop starting; running bodies drain below
                }
                group.addTask {
                    await body(element)
                    await slots.release()
                }
            }
        }
    }
}

/// FIFO counting gate for BoundedConcurrency runs that share one limit.
/// Each `acquire` states the limit it runs under (read from Settings when
/// its batch began), so a lowered setting throttles new starts while
/// transfers already running finish. A granted slot must be released
/// exactly once.
actor AsyncSlots {
    private var held = 0
    private var waiters: [(limit: Int, continuation: CheckedContinuation<Void, Never>)] = []

    /// Bodies currently holding a slot (tests / diagnostics).
    var inUse: Int { held }

    /// Returns once a slot is free (`limit` below 1 is treated as 1).
    /// Waiters are served strictly in arrival order.
    func acquire(limit: Int) async {
        let limit = max(1, limit)
        if waiters.isEmpty, held < limit {
            held += 1
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append((limit, continuation))
        }
    }

    func release() {
        held = max(0, held - 1)
        // Hand freed slots to the oldest waiters whose limit allows it.
        while let first = waiters.first, held < first.limit {
            waiters.removeFirst()
            held += 1
            first.continuation.resume()
        }
    }
}
