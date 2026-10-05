// Nucleon Transfer — best-effort zeroing of secret buffers (F8.1-S7).
// memset_s is never elided by the optimizer (C11 Annex K), unlike a plain
// loop over a buffer that is about to die.
//
// Limits (why this is "best-effort"): Array and Data are copy-on-write. A
// wipe writes through a MUTABLE view, so when the storage is still shared
// with another live value Swift first copies it and zeroes the copy — the
// shared bytes are left to ARC. Call sites therefore wipe only after every
// other reference is gone (end of scope, after the callee returned).
// Swift `String`s (the password field) and CryptoKit key types cannot be
// wiped from here at all.
import Foundation

enum SecureBytes {
    /// Zeroes every element in place; the count is unchanged.
    static func wipe<T: BitwiseCopyable>(_ buffer: inout [T]) {
        buffer.withUnsafeMutableBytes { zero($0) }
    }

    /// Zeroes every byte in place; the count is unchanged.
    static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { zero($0) }
    }

    private static func zero(_ raw: UnsafeMutableRawBufferPointer) {
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        _ = memset_s(base, raw.count, 0, raw.count)
    }
}

extension Array where Element == KeyringCache.UnlockedKey {
    /// Zeroes each key's seed in place (see SecureBytes limits).
    mutating func wipeSeeds() {
        for i in indices { SecureBytes.wipe(&self[i].seed) }
    }
}
