// Nucleon Transfer — bounded parallel for-each (F8.4-U7b).
// Runs one async body per element with at most `width` in flight, starting
// elements in order. `shouldStart` is consulted (on the caller's isolation)
// right before each start: once it answers false nothing new starts, and
// the call returns after the running bodies finish. Used by
// DownloadCoordinator for "Simultaneous downloads" — the per-item Task,
// record and cancellation stay with the caller; this only paces starts.

import Foundation

enum BoundedConcurrency {
    /// `width` below 1 is treated as 1 (sequential).
    static func forEach<Element: Sendable>(
        _ elements: [Element],
        width: Int,
        isolation: isolated (any Actor)? = #isolation,
        shouldStart: () -> Bool = { true },
        _ body: @escaping @Sendable (Element) async -> Void
    ) async {
        let width = max(1, width)
        await withTaskGroup(of: Void.self) { group in
            var next = 0
            var running = 0
            while next < elements.count || running > 0 {
                while next < elements.count, running < width {
                    guard shouldStart() else {
                        next = elements.count // stop starting; drain below
                        break
                    }
                    let element = elements[next]
                    next += 1
                    running += 1
                    group.addTask { await body(element) }
                }
                guard running > 0 else { break }
                await group.next()
                running -= 1
            }
        }
    }
}
