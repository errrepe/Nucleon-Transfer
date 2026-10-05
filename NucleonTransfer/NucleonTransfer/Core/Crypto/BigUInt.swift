// Nucleon Transfer — minimal unsigned big integer for SRP-6a (up to 2048-bit).
// Wire format: fixed-size LITTLE-endian Data (matches go-srp toInt/fromInt).
//
// DESIGN: 32-bit limbs. Every intermediate (a*b + acc + carry with a,b,acc
// < 2^32) is < 2^64, so plain UInt64 arithmetic is EXACT — no fullWidth,
// no wrap-prone carry chains. Slower per-op than 64-bit limbs, but obviously
// correct; a login needs only a handful of 2048-bit modPows.
// modPow with an odd modulus (every SRP modulus) runs on a separate 64-bit
// limb Montgomery core below (F8.3-P5); the 32-bit code is only used for the
// cheap surrounding arithmetic.
import Foundation

struct BigUInt: Sendable, Equatable {
    /// Little-endian 32-bit limbs, normalized (no trailing zero limbs except [0]).
    var limbs: [UInt32]

    init(limbs: [UInt32]) {
        var l = limbs
        while l.count > 1 && l.last == 0 { l.removeLast() }
        self.limbs = l
    }

    static let zero = BigUInt(limbs: [0])
    static let one = BigUInt(limbs: [1])
    static let two = BigUInt(limbs: [2])

    var isZero: Bool { limbs.count == 1 && limbs[0] == 0 }
    var isOne: Bool { limbs.count == 1 && limbs[0] == 1 }
    var isEven: Bool { (limbs[0] & 1) == 0 }

    init(dataLE: Data) {
        var limbs: [UInt32] = []
        var i = dataLE.startIndex
        while i < dataLE.endIndex {
            var word: UInt32 = 0
            var shift = 0
            for _ in 0..<4 {
                guard i < dataLE.endIndex else { break }
                word |= UInt32(dataLE[i]) << shift
                shift += 8
                i = dataLE.index(after: i)
            }
            limbs.append(word)
        }
        self.init(limbs: limbs.isEmpty ? [0] : limbs)
    }

    func toDataLE(length: Int) -> Data {
        var out = Data(repeating: 0, count: length)
        var idx = 0
        for limb in limbs {
            for b in 0..<4 where idx < length {
                out[idx] = UInt8((limb >> (b * 8)) & 0xFF)
                idx += 1
            }
        }
        return out
    }

    func compare(_ other: BigUInt) -> Int {
        if limbs.count != other.limbs.count {
            return limbs.count < other.limbs.count ? -1 : 1
        }
        for i in stride(from: limbs.count - 1, through: 0, by: -1) {
            if limbs[i] != other.limbs[i] {
                return limbs[i] < other.limbs[i] ? -1 : 1
            }
        }
        return 0
    }

    static func add(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        let n = max(a.limbs.count, b.limbs.count)
        var out: [UInt32] = []
        out.reserveCapacity(n + 1)
        var carry: UInt64 = 0
        for i in 0..<n {
            let x: UInt64 = i < a.limbs.count ? UInt64(a.limbs[i]) : 0
            let y: UInt64 = i < b.limbs.count ? UInt64(b.limbs[i]) : 0
            let t = x + y + carry // < 2^33, exact
            out.append(UInt32(t & 0xFFFF_FFFF))
            carry = t >> 32
        }
        if carry > 0 { out.append(UInt32(carry)) }
        return BigUInt(limbs: out)
    }

    /// Requires a >= b.
    static func sub(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        precondition(a.compare(b) >= 0, "sub requires a >= b")
        var out: [UInt32] = []
        out.reserveCapacity(a.limbs.count)
        var borrow: UInt64 = 0
        for i in 0..<a.limbs.count {
            let x = UInt64(a.limbs[i])
            let y: UInt64 = i < b.limbs.count ? UInt64(b.limbs[i]) : 0
            // y + borrow <= 2^32 < 2^64: no overflow. Underflow iff x < y + borrow.
            let sub = y + borrow
            let res = x &- sub
            out.append(UInt32(res & 0xFFFF_FFFF))
            borrow = x < sub ? 1 : 0
        }
        return BigUInt(limbs: out)
    }

    static func mul(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        if a.isZero || b.isZero { return .zero }
        var out = [UInt32](repeating: 0, count: a.limbs.count + b.limbs.count)
        for i in 0..<a.limbs.count {
            var carry: UInt64 = 0
            for j in 0..<b.limbs.count {
                // max: (2^32-1)^2 + (2^32-1) + carry(<2^32) = 2^64-1 exactly. Exact.
                let t = UInt64(a.limbs[i]) * UInt64(b.limbs[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(t & 0xFFFF_FFFF)
                carry = t >> 32
            }
            var k = i + b.limbs.count
            var c = carry
            while c > 0 {
                let t = UInt64(out[k]) + c // < 2^33, exact
                out[k] = UInt32(t & 0xFFFF_FFFF)
                c = t >> 32
                k += 1
            }
        }
        return BigUInt(limbs: out)
    }

    /// Remainder via Knuth Algorithm D long division, composed ONLY of exact
    /// add/sub/mul/compare above. Estimate never undershoots ( Knuth Thm A
    /// needs no normalization for the >= direction), verify loop decrements
    /// to the exact digit, subtraction is exact.
    static func mod(_ a: BigUInt, _ m: BigUInt) -> BigUInt {
        precondition(!m.isZero, "mod by zero")
        if a.compare(m) < 0 { return a }
        return divmod(a, m).r
    }

    /// Long division. Requires a >= m > 0.
    static func divmod(_ a: BigUInt, _ m: BigUInt) -> (q: BigUInt, r: BigUInt) {
        precondition(!m.isZero && a.compare(m) >= 0, "divmod requires a >= m > 0")
        if m.limbs.count == 1 {
            let d = UInt64(m.limbs[0])
            var rem: UInt64 = 0
            var q = [UInt32](repeating: 0, count: a.limbs.count)
            for i in stride(from: a.limbs.count - 1, through: 0, by: -1) {
                let t = (rem << 32) | UInt64(a.limbs[i]) // rem < d <= 2^32-1: exact
                q[i] = UInt32(t / d)
                rem = t % d
            }
            return (BigUInt(limbs: q), BigUInt(limbs: [UInt32(rem)]))
        }

        let n = m.limbs.count
        let mm = a.limbs.count - n
        var un = a.limbs
        while un.count < mm + n + 1 { un.append(0) }
        let vn = m.limbs
        let vBig = BigUInt(limbs: vn)
        var q = [UInt32](repeating: 0, count: mm + 1)

        for j in stride(from: mm, through: 0, by: -1) {
            // Estimate from top two window words / top divisor word.
            // Numerator < 2^64 (top window word < divisor top word by invariant),
            // so plain UInt64 division is exact. Clamp to base-1.
            var qhat: UInt64
            if un[j + n] == vn[n - 1] {
                qhat = UInt64(UInt32.max)
            } else {
                let num = (UInt64(un[j + n]) << 32) | UInt64(un[j + n - 1])
                qhat = num / UInt64(vn[n - 1])
                if qhat > UInt64(UInt32.max) { qhat = UInt64(UInt32.max) }
            }
            // Decrement until qhat * vn fits the window (exact check).
            var prod = mul(BigUInt(limbs: [UInt32(qhat & 0xFFFF_FFFF), UInt32(qhat >> 32)]), vBig)
            var window = BigUInt(limbs: Array(un[j..<(j + n + 1)]))
            while prod.compare(window) > 0 {
                qhat -= 1
                prod = mul(BigUInt(limbs: [UInt32(qhat & 0xFFFF_FFFF), UInt32(qhat >> 32)]), vBig)
            }
            window = sub(window, prod)
            for i in 0...(n) {
                un[j + i] = i < window.limbs.count ? window.limbs[i] : 0
            }
            q[j] = UInt32(qhat & 0xFFFF_FFFF)
            assert(qhat <= UInt64(UInt32.max), "quotient digit must fit 32 bits")
        }
        return (BigUInt(limbs: q), BigUInt(limbs: Array(un.prefix(n))))
    }

    static func modMul(_ a: BigUInt, _ b: BigUInt, _ m: BigUInt) -> BigUInt {
        mod(mul(a, b), m)
    }

    /// base^exp mod m. Odd moduli > 1 (every SRP modulus) use Montgomery
    /// multiplication with a fixed 4-bit window (F8.3-P5); even moduli and
    /// m == 1 keep the plain square-and-multiply path.
    static func modPow(_ base: BigUInt, _ exp: BigUInt, _ mod_: BigUInt) -> BigUInt {
        precondition(!mod_.isZero, "modpow by zero")
        if mod_.isEven || mod_.isOne {
            return modPowSquareMultiply(base, exp, mod_)
        }
        return Montgomery.pow(mod(base, mod_), exp, mod_)
    }

    /// Reference path: right-to-left square-and-multiply over full long
    /// division. Variable-time and slow; only for even moduli (no caller has
    /// one today) and m == 1.
    static func modPowSquareMultiply(_ base: BigUInt, _ exp: BigUInt, _ mod_: BigUInt) -> BigUInt {
        precondition(!mod_.isZero, "modpow by zero")
        var result = BigUInt.one
        var b = mod(base, mod_)
        var e = exp
        while !e.isZero {
            if (e.limbs[0] & 1) == 1 {
                result = mod(mul(result, b), mod_)
            }
            e = e.shr1()
            b = mod(mul(b, b), mod_)
        }
        return result
    }

    var bitLength: Int {
        guard let top = limbs.last, top != 0 else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    func shl(_ bits: Int) -> BigUInt {
        if isZero || bits == 0 { return self }
        let words = bits / 32, rem = bits % 32
        var out = [UInt32](repeating: 0, count: limbs.count + words + 1)
        var carry: UInt32 = 0
        for i in 0..<limbs.count {
            let v = UInt64(limbs[i])
            out[i + words] = UInt32((v << rem) & 0xFFFF_FFFF) | carry
            carry = rem == 0 ? 0 : UInt32((v >> (32 - rem)) & 0xFFFF_FFFF)
        }
        out[limbs.count + words] = carry
        return BigUInt(limbs: out)
    }

    func shr1() -> BigUInt {
        var out = [UInt32](repeating: 0, count: limbs.count)
        var carry: UInt32 = 0
        for i in stride(from: limbs.count - 1, through: 0, by: -1) {
            let v = limbs[i]
            out[i] = (v >> 1) | (carry << 31)
            carry = v & 1
        }
        return BigUInt(limbs: out)
    }
}

// MARK: - Montgomery exponentiation (F8.3-P5)

/// Montgomery modular exponentiation for an odd modulus n > 1.
///
/// Internals use 64-bit limbs and CIOS (Coarsely Integrated Operand
/// Scanning) multiplication: one interleaved multiply/reduce pass, no
/// division, all operands in one preallocated scratch arena, 64x64->128
/// products via `multipliedFullWidth`.
///
/// Exponent processing is a fixed 4-bit window, left to right: every window
/// costs exactly 4 squarings + 1 multiplication, the window count depends
/// only on max(exp limb count, modulus size), and the table entry is chosen by
/// scanning all 16 entries with masks (no secret-indexed memory access). The
/// final reduction in `mul` is a masked select, not a branch.
///
/// What is NOT constant-time (best-effort, honest list):
/// - Swift gives no constant-time codegen guarantee; the masks are written
///   branch-free but the optimizer could in principle reintroduce branches.
/// - The window count leaks the exponent's normalized 32-bit limb count when
///   it exceeds the modulus size (SRP exponents are < 2^2048, so it doesn't).
/// - `BigUInt.mod(base, n)` before entry is the variable-time Knuth division
///   (a no-op when base < n, as in SRP); R^2 mod n branches, but on n only.
/// - Everything around modPow in SRP (`modMul`, `mod`, `sub`, `compare`,
///   array allocation and normalization) is still the variable-time
///   32-bit-limb code.
private enum Montgomery {
    /// Window width in bits. 4 divides 32, so a window never straddles limbs.
    static let windowBits = 4
    static let tableSize = 1 << windowBits

    static func pow(_ base: BigUInt, _ exp: BigUInt, _ modulus: BigUInt) -> BigUInt {
        precondition(!modulus.isEven && !modulus.isOne, "Montgomery needs an odd modulus > 1")
        precondition(base.compare(modulus) < 0, "base must be reduced")
        let s = (modulus.limbs.count + 1) / 2 // 64-bit limbs

        // Arena layout (each slot s limbs): n, rr, base, one, acc, tmp,
        // table[16]; plus s+2 limbs of CIOS scratch.
        let slots = 6 + tableSize
        let total = slots * s + s + 2
        let arena = UnsafeMutablePointer<UInt64>.allocate(capacity: total)
        arena.initialize(repeating: 0, count: total)
        defer {
            // Table and accumulator hold secret-derived powers: zero them.
            _ = memset_s(arena, total * 8, 0, total * 8)
            arena.deallocate()
        }
        let n = arena, rrM = arena + s, baseM = arena + 2 * s, one = arena + 3 * s
        let acc = arena + 4 * s, tmp = arena + 5 * s, table = arena + 6 * s
        let t = arena + slots * s

        load(modulus, into: n, count: s)
        squareOfR(n: n, bitLength: modulus.bitLength, s: s, into: rrM)
        load(base, into: baseM, count: s)
        one[0] = 1
        let n0inv = negInverse(n[0])

        // table[0] = R mod n (Montgomery 1), table[1] = base*R mod n, ...
        mul(rrM, one, into: table, n: n, n0inv: n0inv, s: s, t: t)
        mul(baseM, rrM, into: table + s, n: n, n0inv: n0inv, s: s, t: t)
        for i in 2..<tableSize {
            mul(table + (i - 1) * s, table + s, into: table + i * s, n: n, n0inv: n0inv, s: s, t: t)
        }

        // Fixed window count: covers the exponent and at least the modulus width.
        let expBits = max(exp.limbs.count, modulus.limbs.count) * 32
        let windows = expBits / windowBits
        acc.update(from: table, count: s) // Montgomery 1
        for w in stride(from: windows - 1, through: 0, by: -1) {
            for _ in 0..<windowBits {
                mul(acc, acc, into: acc, n: n, n0inv: n0inv, s: s, t: t)
            }
            // Window position is public; only the digit value is secret.
            let pos = w * windowBits
            let limb = pos / 32
            let digit = limb < exp.limbs.count ? Int((exp.limbs[limb] >> UInt32(pos % 32)) & 0xF) : 0
            select(table, digit, into: tmp, s: s)
            mul(acc, tmp, into: acc, n: n, n0inv: n0inv, s: s, t: t)
        }
        // Leave Montgomery form: acc * 1 * R^-1.
        mul(acc, one, into: tmp, n: n, n0inv: n0inv, s: s, t: t)

        var out = [UInt32](repeating: 0, count: 2 * s)
        for i in 0..<s {
            out[2 * i] = UInt32(truncatingIfNeeded: tmp[i])
            out[2 * i + 1] = UInt32(truncatingIfNeeded: tmp[i] >> 32)
        }
        return BigUInt(limbs: out)
    }

    /// 32-bit limbs -> zero-padded 64-bit limbs.
    private static func load(_ x: BigUInt, into dst: UnsafeMutablePointer<UInt64>, count s: Int) {
        for i in 0..<s {
            let lo = 2 * i < x.limbs.count ? UInt64(x.limbs[2 * i]) : 0
            let hi = 2 * i + 1 < x.limbs.count ? UInt64(x.limbs[2 * i + 1]) : 0
            dst[i] = lo | (hi << 32)
        }
    }

    /// RR = R^2 mod n with R = 2^(64*s), by modular doubling from
    /// 2^(bitLength-1) < n. Avoids `BigUInt.divmod`, whose quotient-digit
    /// correction loop degenerates for moduli with a small top limb.
    /// Depends on n only (public).
    private static func squareOfR(n: UnsafeMutablePointer<UInt64>, bitLength: Int, s: Int,
                                  into x: UnsafeMutablePointer<UInt64>) {
        for j in 0..<s { x[j] = 0 }
        let top = bitLength - 1
        x[top / 64] = 1 << UInt64(top % 64)
        for _ in 0..<(128 * s - top) {
            // x = 2x (carry-out c), then x -= n iff 2x >= n.
            var c: UInt64 = 0
            for j in 0..<s {
                let v = x[j]
                x[j] = (v << 1) | c
                c = v >> 63
            }
            // Compare pass (borrow of x - n), then subtract if needed.
            var borrow: UInt64 = 0
            for j in 0..<s {
                let (d1, b1) = x[j].subtractingReportingOverflow(n[j])
                borrow = bit(b1) | bit(d1.subtractingReportingOverflow(borrow).overflow)
            }
            if c == 1 || borrow == 0 {
                borrow = 0
                for j in 0..<s {
                    let (d1, b1) = x[j].subtractingReportingOverflow(n[j])
                    let (d2, b2) = d1.subtractingReportingOverflow(borrow)
                    x[j] = d2
                    borrow = bit(b1) | bit(b2)
                }
            }
        }
    }

    /// -n0^-1 mod 2^64 by Newton iteration (n0 odd; n0*n0 == 1 mod 8 gives
    /// 3 correct bits, each step doubles them: 3 -> 6 -> 12 -> 24 -> 48 -> 96).
    private static func negInverse(_ n0: UInt64) -> UInt64 {
        var inv = n0
        for _ in 0..<5 { inv = inv &* (2 &- n0 &* inv) }
        return 0 &- inv
    }

    /// Constant-time table lookup: reads every entry, keeps the one whose
    /// index equals `digit` via an all-ones/all-zeros mask.
    private static func select(_ table: UnsafeMutablePointer<UInt64>, _ digit: Int,
                               into dst: UnsafeMutablePointer<UInt64>, s: Int) {
        for j in 0..<s { dst[j] = 0 }
        let d = UInt64(truncatingIfNeeded: digit)
        for i in 0..<tableSize {
            let diff = UInt64(truncatingIfNeeded: i) ^ d
            // nonZero = 1 iff diff != 0 (top bit of diff | -diff).
            let nonZero = (diff | (0 &- diff)) >> 63
            let mask = nonZero &- 1 // all ones iff i == digit
            let entry = table + i * s
            for j in 0..<s { dst[j] |= entry[j] & mask }
        }
    }

    /// Carry/borrow flag as 0 or 1 without a conditional (Bool is one byte
    /// holding 0 or 1); `flag ? 1 : 0` measurably slows the release build
    /// and may compile to a branch.
    @inline(__always)
    private static func bit(_ flag: Bool) -> UInt64 {
        UInt64(unsafeBitCast(flag, to: UInt8.self))
    }

    /// out = a * b * R^-1 mod n (CIOS). Requires a, b < n. `out` may alias
    /// `a` or `b` (all reads finish before the first write to `out`); `t` is
    /// s+2 limbs of scratch and must not alias anything else.
    /// Each limb step is x*y + t + carry <= (2^64-1)^2 + 2(2^64-1) = 2^128-1,
    /// so (hi, lo) plus the two carry bits never overflows `hi`.
    private static func mul(_ a: UnsafeMutablePointer<UInt64>, _ b: UnsafeMutablePointer<UInt64>,
                            into out: UnsafeMutablePointer<UInt64>,
                            n: UnsafeMutablePointer<UInt64>, n0inv: UInt64, s: Int,
                            t: UnsafeMutablePointer<UInt64>) {
        for j in 0..<(s + 2) { t[j] = 0 }
        for i in 0..<s {
            // t += a * b[i]
            let bi = b[i]
            var carry: UInt64 = 0
            for j in 0..<s {
                let (hi, lo) = a[j].multipliedFullWidth(by: bi)
                let (s1, c1) = lo.addingReportingOverflow(t[j])
                let (s2, c2) = s1.addingReportingOverflow(carry)
                t[j] = s2
                carry = hi &+ bit(c1) &+ bit(c2)
            }
            let (top, ct) = t[s].addingReportingOverflow(carry)
            t[s] = top
            t[s + 1] = bit(ct)

            // t = (t + m*n) / 2^64, with m chosen so the low limb cancels.
            let m = t[0] &* n0inv
            let (h0, l0) = m.multipliedFullWidth(by: n[0])
            carry = h0 &+ bit(l0.addingReportingOverflow(t[0]).overflow) // low limb -> 0
            for j in 1..<s {
                let (hi, lo) = m.multipliedFullWidth(by: n[j])
                let (s1, c1) = lo.addingReportingOverflow(t[j])
                let (s2, c2) = s1.addingReportingOverflow(carry)
                t[j - 1] = s2
                carry = hi &+ bit(c1) &+ bit(c2)
            }
            let (up, cu) = t[s].addingReportingOverflow(carry)
            t[s - 1] = up
            t[s] = t[s + 1] &+ bit(cu)
        }

        // t < 2n. out = t - n, then keep it iff t >= n, i.e. t[s] == 1 or
        // no final borrow (masked select, no branch).
        var borrow: UInt64 = 0
        for j in 0..<s {
            let (d1, b1) = t[j].subtractingReportingOverflow(n[j])
            let (d2, b2) = d1.subtractingReportingOverflow(borrow)
            out[j] = d2
            borrow = bit(b1) | bit(b2) // at most one of b1, b2
        }
        let keepDiff = (t[s] | (borrow ^ 1)) & 1
        let mask = 0 &- keepDiff
        for j in 0..<s { out[j] = (out[j] & mask) | (t[j] & ~mask) }
    }
}
