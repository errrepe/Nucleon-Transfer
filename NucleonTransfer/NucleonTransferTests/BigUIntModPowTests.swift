// Nucleon Transfer — Montgomery modPow vs. reference square-and-multiply (F8.3-P5).
// The reference below is the pre-F8.3 algorithm, kept verbatim on top of the
// exact 32-bit-limb mul/mod so the fast path is checked against independent
// code. Inputs are deterministic (seeded SplitMix64). NO network, NO secrets.
import Foundation
import Testing

@testable import NucleonTransfer

/// Pre-F8.3 BigUInt.modPow (right-to-left square-and-multiply, Knuth mod per step).
private func referenceModPow(_ base: BigUInt, _ exp: BigUInt, _ m: BigUInt) -> BigUInt {
    var result = BigUInt.one
    var b = BigUInt.mod(base, m)
    var e = exp
    while !e.isZero {
        if (e.limbs[0] & 1) == 1 { result = BigUInt.mod(BigUInt.mul(result, b), m) }
        e = e.shr1()
        b = BigUInt.mod(BigUInt.mul(b, b), m)
    }
    return result
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
    /// Random odd modulus of exactly `count` 32-bit limbs (top bit set).
    mutating func oddModulus(_ count: Int) -> BigUInt {
        var l = limbs(count)
        l[0] |= 1
        l[count - 1] |= 0x8000_0000
        return BigUInt(limbs: l)
    }
}

/// go-srp testModulus (Proton's 2048-bit SRP modulus, a safe prime).
private let srpModulusB64 = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="

struct BigUIntModPowTests {
    /// Full-length random exponents at every modulus size up to 512 bits,
    /// including odd 32-bit limb counts (high half of the top 64-bit limb 0)
    /// and bases larger than the modulus.
    @Test func matchesReferenceSmallAndMidSizes() {
        var rng = SplitMix64(state: 0x5EED_0001)
        for size in 1...16 {
            for _ in 0..<2 {
                let m = rng.oddModulus(size)
                let base = BigUInt(limbs: rng.limbs(size + 1))
                let exp = BigUInt(limbs: rng.limbs(size))
                #expect(BigUInt.modPow(base, exp, m) == referenceModPow(base, exp, m),
                        "size \(size)")
            }
        }
    }

    /// Large moduli (up to 2048 bits) with short exponents so the slow
    /// reference stays fast in debug; exponent longer than the modulus too.
    @Test func matchesReferenceLargeModuli() {
        var rng = SplitMix64(state: 0x5EED_0002)
        for size in [17, 33, 63, 64] {
            let m = rng.oddModulus(size)
            let base = BigUInt(limbs: rng.limbs(size))
            for expLimbs in [1, 2] {
                let exp = BigUInt(limbs: rng.limbs(expLimbs))
                #expect(BigUInt.modPow(base, exp, m) == referenceModPow(base, exp, m),
                        "size \(size) exp \(expLimbs)")
            }
        }
        // Exponent with more limbs than a small modulus.
        let m = rng.oddModulus(3)
        let base = BigUInt(limbs: rng.limbs(3)), exp = BigUInt(limbs: rng.limbs(9))
        #expect(BigUInt.modPow(base, exp, m) == referenceModPow(base, exp, m))
    }

    @Test func edgeCases() {
        // Top limb with its high bit set: the reference's long division is
        // only fast for normalized divisors (see smallTopLimbKnownAnswers).
        let m = BigUInt(limbs: [0xFFFF_FFFB, 0xFFFF_FFFF, 0x8000_1234]) // odd
        let mMinus1 = BigUInt.sub(m, .one)
        let x = BigUInt(limbs: [0xDEAD_BEEF, 0x0BAD_F00D, 0x77])
        #expect(BigUInt.modPow(x, .zero, m) == .one)
        #expect(BigUInt.modPow(.zero, x, m) == .zero)
        #expect(BigUInt.modPow(.one, x, m) == .one)
        #expect(BigUInt.modPow(x, .one, m) == x)
        #expect(BigUInt.modPow(m, x, m) == .zero)           // base == m
        #expect(BigUInt.modPow(mMinus1, BigUInt(limbs: [2]), m) == .one) // (-1)^2
        #expect(BigUInt.modPow(mMinus1, x, m) == mMinus1)   // (-1)^odd
        let allOnes = BigUInt(limbs: [UInt32](repeating: .max, count: 5))
        #expect(BigUInt.modPow(x, allOnes, m) == referenceModPow(x, allOnes, m))
        // Single-limb moduli, including the smallest odd one.
        for small: UInt32 in [3, 5, 7, 0xFFFF_FFFF] {
            let sm = BigUInt(limbs: [small])
            #expect(BigUInt.modPow(x, x, sm) == referenceModPow(x, x, sm))
        }
    }

    /// Modulus whose top 32-bit limb is small. The pre-F8.3 path takes ~20 s
    /// (release) here because `divmod` does not normalize the divisor, so the
    /// expected values come from Python's pow() instead.
    @Test func smallTopLimbKnownAnswers() {
        let m = BigUInt(limbs: [0xFFFF_FFFB, 0xFFFF_FFFF, 0x1234])
        let x = BigUInt(limbs: [0xDEAD_BEEF, 0x0BAD_F00D, 0x77])
        let allOnes = BigUInt(limbs: [UInt32](repeating: .max, count: 5)) // 2^160 - 1
        #expect(BigUInt.modPow(x, allOnes, m) == BigUInt(limbs: [0x3452_3DA6, 0x81DF_97A1, 0x355]))
        #expect(BigUInt.modPow(x, x, m) == BigUInt(limbs: [0x7D65_C518, 0x2A5E_B871, 0xCCE]))
        #expect(BigUInt.modPow(BigUInt.sub(m, .one), x, m) == BigUInt.sub(m, .one))
    }

    /// Even moduli and m == 1 keep the old path (behaviour unchanged).
    @Test func evenModulusAndOneUseFallback() {
        var rng = SplitMix64(state: 0x5EED_0003)
        for size in [1, 2, 5, 8] {
            var l = rng.limbs(size)
            l[0] &= ~1
            l[size - 1] |= 0x8000_0000
            let m = BigUInt(limbs: l)
            let base = BigUInt(limbs: rng.limbs(size)), exp = BigUInt(limbs: rng.limbs(size))
            #expect(BigUInt.modPow(base, exp, m) == referenceModPow(base, exp, m))
        }
        let x = BigUInt(limbs: [12345])
        #expect(BigUInt.modPow(x, .zero, .one) == referenceModPow(x, .zero, .one))
        #expect(BigUInt.modPow(x, x, .one) == .zero)
    }

    /// Fermat on the real SRP modulus with full 2048-bit exponents:
    /// N is prime, so a^(N-1) == 1 and a^N == a.
    @Test func fermatOnSRPModulus() throws {
        let n = BigUInt(dataLE: try #require(Data(base64Encoded: srpModulusB64)))
        #expect(n.bitLength == 2048)
        let nMinus1 = BigUInt.sub(n, .one)
        var rng = SplitMix64(state: 0x5EED_0004)
        let a = BigUInt.mod(BigUInt(limbs: rng.limbs(64)), n)
        #expect(BigUInt.modPow(a, nMinus1, n) == .one)
        #expect(BigUInt.modPow(a, n, n) == a)
    }
}
