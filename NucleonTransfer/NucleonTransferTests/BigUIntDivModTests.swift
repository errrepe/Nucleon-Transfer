// Nucleon Transfer — BigUInt.divmod (Knuth D with normalization) vs. bit-by-bit reference (F8.3-P6).
// The reference is schoolbook binary long division built only on shl/add/
// sub/compare, so it is independent of the limb-level quotient estimate.
// Inputs are deterministic (seeded SplitMix64). NO network, NO secrets.
import Foundation
import Testing

@testable import NucleonTransfer

/// Binary long division: one quotient bit per dividend bit, top down.
private func referenceDivMod(_ a: BigUInt, _ m: BigUInt) -> (q: BigUInt, r: BigUInt) {
    var r = BigUInt.zero
    var q = [UInt32](repeating: 0, count: a.limbs.count)
    for bit in stride(from: a.bitLength - 1, through: 0, by: -1) {
        r = r.shl(1)
        if (a.limbs[bit / 32] >> UInt32(bit % 32)) & 1 == 1 { r = BigUInt.add(r, .one) }
        if r.compare(m) >= 0 {
            r = BigUInt.sub(r, m)
            q[bit / 32] |= 1 << UInt32(bit % 32)
        }
    }
    return (BigUInt(limbs: q), r)
}

/// Deterministic test RNG (SplitMix64).
private struct SplitMix64 {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
    mutating func limbs(_ count: Int) -> [UInt32] {
        (0..<count).map { _ in UInt32(truncatingIfNeeded: next()) }
    }
    /// Non-zero limbs with the top limb forced to a chosen shape.
    mutating func number(_ count: Int, top: UInt32? = nil) -> BigUInt {
        var l = limbs(count)
        if let top { l[count - 1] = top } else if l[count - 1] == 0 { l[count - 1] = 1 }
        return BigUInt(limbs: l)
    }
}

struct BigUIntDivModTests {
    private func check(_ a: BigUInt, _ m: BigUInt, _ note: String) {
        guard a.compare(m) >= 0 else { return }
        let (q, r) = BigUInt.divmod(a, m)
        let ref = referenceDivMod(a, m)
        #expect(q == ref.q, "q \(note)")
        #expect(r == ref.r, "r \(note)")
        #expect(r.compare(m) < 0, "r < m \(note)")
        #expect(BigUInt.add(BigUInt.mul(q, m), r) == a, "q*m + r == a \(note)")
    }

    /// Random sizes, random top limbs (mostly not normalized: every shift
    /// 0...31 shows up across the run).
    @Test func matchesReferenceRandom() {
        var rng = SplitMix64(state: 0xD1F0_0001)
        for divLimbs in 1...9 {
            for extra in 0...6 {
                for _ in 0..<3 {
                    let m = rng.number(divLimbs)
                    let a = rng.number(divLimbs + extra)
                    check(a, m, "div \(divLimbs) extra \(extra)")
                }
            }
        }
    }

    /// Every normalization shift, with tiny and saturated top limbs, plus
    /// all-ones dividends (worst case for the quotient estimate).
    @Test func smallAndExtremeTopLimbs() {
        var rng = SplitMix64(state: 0xD1F0_0002)
        for shift in 0..<32 {
            let topValues: [UInt32] = [1 << UInt32(31 - shift), (UInt32.max >> UInt32(shift))]
            for top in topValues {
                for divLimbs in [2, 3, 5] {
                    let m = rng.number(divLimbs, top: top)
                    check(rng.number(divLimbs + 3), m, "shift \(shift) top \(top)")
                    check(BigUInt(limbs: [UInt32](repeating: .max, count: divLimbs + 2)), m,
                          "all ones, shift \(shift)")
                    check(m, m, "a == m")
                    check(BigUInt.add(m, .one), m, "a == m + 1")
                }
            }
        }
        // The P5 case: 96-bit divisor, top limb 0x1234, low limbs all ones.
        let m = BigUInt(limbs: [0xFFFF_FFFB, 0xFFFF_FFFF, 0x1234])
        check(BigUInt(limbs: [UInt32](repeating: .max, count: 6)), m, "0x1234")
        check(BigUInt.mul(m, m), m, "m^2")
        check(BigUInt.sub(BigUInt.mul(m, m), .one), m, "m^2 - 1")
    }

    /// Divisor limbs that force the D6 add-back (qhat one too large after
    /// the D3 refinement): Knuth's classic pattern with a zero middle limb.
    @Test func addBackCases() {
        let cases: [([UInt32], [UInt32])] = [
            ([0, 0, 0x8000_0000, 0x7FFF_FFFF], [1, 0, 0x8000_0000]),
            ([0, 0xFFFF_FFFE, 0, 0x8000_0000], [0xFFFF_FFFF, 0, 0x8000_0000]),
            ([3, 0, 0x8000_0000], [1, 0, 0x2000_0000]),
            ([0, 0, 0x8000, 0x7FFF], [1, 0, 0x8000]),
        ]
        for (a, m) in cases {
            check(BigUInt(limbs: a), BigUInt(limbs: m), "\(a) / \(m)")
        }
    }

    /// The square-and-multiply path on a 96-bit modulus with top limb 0x1234
    /// took ~19 s before normalization; now it is milliseconds even in debug.
    @Test func smallTopLimbDivisionIsFast() {
        let m = BigUInt(limbs: [0xFFFF_FFFB, 0xFFFF_FFFF, 0x1234])
        let x = BigUInt(limbs: [0xDEAD_BEEF, 0x0BAD_F00D, 0x77])
        let allOnes = BigUInt(limbs: [UInt32](repeating: .max, count: 5))
        let clock = ContinuousClock()
        var result = BigUInt.zero
        let elapsed = clock.measure {
            result = BigUInt.modPowSquareMultiply(x, allOnes, m)
        }
        // Known answer from Python's pow() (same as BigUIntModPowTests).
        #expect(result == BigUInt(limbs: [0x3452_3DA6, 0x81DF_97A1, 0x355]))
        #expect(elapsed < .milliseconds(50), "took \(elapsed)")
    }
}
