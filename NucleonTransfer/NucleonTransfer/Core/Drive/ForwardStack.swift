// Nucleon Transfer — browser Back/Forward history (F8.4-U3).
// The folder stack itself is the NavigationStack path, so "Back" is a pop.
// This records what a pop removed so "Forward" can push it again, and
// forgets it when the user navigates somewhere new — Finder semantics.
// Fed with every (old, new) path pair, whatever changed the path (Go menu,
// toolbar, the title-menu breadcrumb, the system back gesture).
import Foundation

struct ForwardStack<Element: Equatable> {
    /// Folders Forward would reopen; `last` is the next one.
    private(set) var items: [Element] = []

    /// The folder Forward pushes next, if any.
    var next: Element? { items.last }
    var canGoForward: Bool { !items.isEmpty }

    /// Updates the history for a path change.
    /// - Pop (new is a strict prefix of old): the removed folders become
    ///   forward entries, nearest first — [A,B,C] → [A] makes Forward
    ///   reopen B, then C.
    /// - Push of exactly `next`: a Forward step (or reopening the same
    ///   folder by hand) — consume it, keep the rest.
    /// - Any other push or replacement: new navigation, history cleared.
    mutating func record(from old: [Element], to new: [Element]) {
        if new.count < old.count, old.starts(with: new) {
            items.append(contentsOf: old[new.count...].reversed())
        } else if new.count == old.count + 1, new.starts(with: old), let pushed = new.last {
            if pushed == items.last {
                items.removeLast()
            } else {
                items.removeAll()
            }
        } else if new != old {
            items.removeAll()
        }
    }
}

extension ForwardStack: Sendable where Element: Sendable {}
