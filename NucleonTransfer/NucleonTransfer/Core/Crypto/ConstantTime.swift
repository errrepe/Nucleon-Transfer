// Nucleon Transfer — constant-time byte comparison for MACs/digests (F8.1-S3).
// Runtime depends only on the lengths, never on where the inputs differ.
// Lengths are not secret here (MDC = 20 bytes, SRP proof = 256 bytes).
import Foundation

/// True iff `a` and `b` have the same length and bytes. Every byte pair is
/// visited and OR-accumulated, so there is no early exit on the first
/// mismatch (unlike `Data.==`).
func constantTimeEquals<A: Collection<UInt8>, B: Collection<UInt8>>(_ a: A, _ b: B) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}
