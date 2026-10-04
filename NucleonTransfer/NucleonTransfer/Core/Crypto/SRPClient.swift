// Nucleon Transfer — SRP-6a client proofs per ProtonMail/go-srp/srp.go
// Generator is always 2. Bit length 2048. Wire ints are fixed-size little-endian.
// Callers pass modulus bytes already verified by ModulusDecoder (pinned-key
// clearsign check); N is still range-checked here (2048 bits, 3 mod 8).
import Foundation

struct SRPProofs: Sendable {
    var clientEphemeral: Data // 256 bytes LE
    var clientProof: Data      // 256 bytes (expandHash output)
    var expectedServerProof: Data
}

enum SRPClient {
    static let bitLength = 2048
    static let byteLength = 256

    static func checkParams(serverEphemeral: BigUInt, modulus: BigUInt) throws {
        let one = BigUInt.one
        let modMinusOne = BigUInt.sub(modulus, one)
        // modulus size
        guard modulus.bitLength == bitLength else {
            throw ProtonAPIError.srpParamsOutOfBounds("modulus size \(modulus.bitLength) != 2048")
        }
        // modulus must be 3 mod 8: bits 0,1 set, bit 2 clear
        let m0 = modulus.limbs[0]
        guard (m0 & 1) == 1, (m0 & 2) == 2, (m0 & 4) == 0 else {
            throw ProtonAPIError.srpParamsOutOfBounds("modulus is not 3 mod 8")
        }
        // 1 < serverEphemeral < N-1
        guard serverEphemeral.compare(one) > 0, serverEphemeral.compare(modMinusOne) < 0 else {
            throw ProtonAPIError.srpParamsOutOfBounds("server ephemeral out of bounds")
        }
    }

    static func multiplier(modulus: BigUInt) throws -> BigUInt {
        // k = expandHash(g || N) mod N, with g=2 and N as fixed LE; must satisfy 1 < k < N-1
        let g = BigUInt.two.toDataLE(length: byteLength)
        let n = modulus.toDataLE(length: byteLength)
        let h = ExpandHash.expand(g + n)
        let k = BigUInt(dataLE: h.prefix(byteLength))
        let kMod = BigUInt.mod(k, modulus)
        let modMinusOne = BigUInt.sub(modulus, .one)
        guard kMod.compare(.one) > 0, kMod.compare(modMinusOne) < 0 else {
            throw ProtonAPIError.srpParamsOutOfBounds("multiplier out of bounds")
        }
        return kMod
    }

    /// Rejection-sampling budget for the client secret. go-srp draws
    /// uniformly in [0, N-1) and loops until > 2*bitLength; we draw 2048
    /// random bits instead, so one draw lands in range with probability
    /// >= ~1/2 (N has its top bit set). 64 draws => failure <= 2^-64.
    static let maxSecretDraws = 64

    /// Full client-side proof generation. `clientSecret` injected for
    /// testability (range-checked like a drawn one); nil draws it from
    /// `randomBytes` (checked SecRandomCopyBytes by default). Throws instead
    /// of ever using an out-of-range secret.
    static func generateProofs(
        hashedPassword: Data,
        serverEphemeral: Data,
        modulus: Data,
        clientSecret: Data? = nil,
        randomBytes: (Int) throws -> Data = SecureRandom.bytes
    ) throws -> SRPProofs {
        guard hashedPassword.count == byteLength else {
            throw ProtonAPIError.srpParamsOutOfBounds("hashed password length \(hashedPassword.count)")
        }
        let n = BigUInt(dataLE: modulus)
        let sEphem = BigUInt(dataLE: serverEphemeral)
        try checkParams(serverEphemeral: sEphem, modulus: n)
        let modulusNat = n
        let modMinusOne = BigUInt.sub(n, .one)

        // client secret: random in (2*bitLength, N-1)
        let lower = BigUInt(limbs: [UInt32(bitLength * 2)])
        func inRange(_ c: BigUInt) -> Bool {
            c.compare(lower) > 0 && c.compare(modMinusOne) < 0
        }
        var secret: BigUInt? = nil
        if let clientSecret {
            let c = BigUInt(dataLE: clientSecret)
            guard inRange(c) else {
                throw ProtonAPIError.srpParamsOutOfBounds("client secret out of range")
            }
            secret = c
        } else {
            for _ in 0..<maxSecretDraws {
                let bytes = try randomBytes(byteLength)
                guard bytes.count == byteLength else { throw ProtonAPIError.secureRandomFailed }
                let c = BigUInt(dataLE: bytes)
                if inRange(c) { secret = c; break }
            }
        }
        guard let secret else {
            throw ProtonAPIError.srpParamsOutOfBounds("could not draw client secret in range")
        }

        let clientEphemeral = BigUInt.modPow(.two, secret, modulusNat)
        let clientEphemData = clientEphemeral.toDataLE(length: byteLength)

        // u = expandHash(A || B) as LE int (scrambling param, must be != 0)
        let uData = ExpandHash.expand(clientEphemData + serverEphemeral)
        let u = BigUInt(dataLE: uData.prefix(byteLength))
        guard !u.isZero else {
            throw ProtonAPIError.srpParamsOutOfBounds("scrambling param is zero, retry")
        }

        let k = try multiplier(modulus: n)
        let x = BigUInt(dataLE: hashedPassword)
        let g: BigUInt = .two

        // base = (B - k * g^x) mod N
        let gx = BigUInt.modPow(g, x, modulusNat)
        let kgx = BigUInt.modMul(k, gx, modulusNat)
        // B >= kgx in valid flows; go-srp ModSub handles wrap, we mirror with +N
        let sEphemNat = sEphem
        let base: BigUInt
        if sEphemNat.compare(kgx) >= 0 {
            base = BigUInt.mod(BigUInt.sub(sEphemNat, kgx), modulusNat)
        } else {
            base = BigUInt.mod(BigUInt.add(BigUInt.sub(modulusNat, kgx), sEphemNat), modulusNat)
        }
        // exp = (u*x + a) mod (N-1)
        let ux = BigUInt.modMul(u, x, modMinusOne)
        let exp = BigUInt.mod(BigUInt.add(ux, secret), modMinusOne)
        let shared = BigUInt.modPow(base, exp, modulusNat)
        let sharedData = shared.toDataLE(length: byteLength)

        let clientProof = ExpandHash.expand(clientEphemData + serverEphemeral + sharedData)
        let serverProof = ExpandHash.expand(clientEphemData + clientProof + sharedData)
        return SRPProofs(clientEphemeral: clientEphemData, clientProof: clientProof, expectedServerProof: serverProof)
    }
}
