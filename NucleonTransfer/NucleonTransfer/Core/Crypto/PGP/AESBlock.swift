// Nucleon Transfer — AES single-block (key wrap) + CFB-128 stream (RFC 4880 §13.9).
// CryptoKit has no ECB/CFB; CommonCrypto provides both. OpenPGP CFB without
// resync (SEIPDv1) is exactly standard CFB-128 with a zero IV over
// prefix || check || data || MDC, so it runs through one CCCryptor
// (F8.3-P1: one key schedule per message instead of one CCCrypt per block).
import CommonCrypto
import Foundation

enum AESError: Error, Sendable {
    case badKeyLength
    case badBlockLength
    case cryptorFailed(CCCryptorStatus)
    case checkBytesMismatch
}

enum AESBlock {
    /// Key lengths: AES-128/192/256. Returns the 16-byte ciphertext block.
    static func encrypt(block: Data, key: Data) throws -> Data {
        guard block.count == kCCBlockSizeAES128 else { throw AESError.badBlockLength }
        let keyLen: Int
        switch key.count {
        case kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256:
            keyLen = key.count
        default:
            throw AESError.badKeyLength
        }
        var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var outLen = 0
        let status = key.withUnsafeBytes { kptr in
            block.withUnsafeBytes { bptr in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    kptr.baseAddress, keyLen,
                    nil,
                    bptr.baseAddress, kCCBlockSizeAES128,
                    &out, out.count,
                    &outLen
                )
            }
        }
        guard status == kCCSuccess, outLen == kCCBlockSizeAES128 else {
            throw AESError.cryptorFailed(status)
        }
        return Data(out)
    }

    /// Raw AES-ECB single-block decrypt (for key unwrap).
    static func decrypt(block: Data, key: Data) throws -> Data {
        guard block.count == kCCBlockSizeAES128 else { throw AESError.badBlockLength }
        switch key.count {
        case kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256:
            break
        default:
            throw AESError.badKeyLength
        }
        var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var outLen = 0
        let status = key.withUnsafeBytes { kptr in
            block.withUnsafeBytes { bptr in
                CCCrypt(
                    CCOperation(kCCDecrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    kptr.baseAddress, key.count,
                    nil,
                    bptr.baseAddress, kCCBlockSizeAES128,
                    &out, out.count,
                    &outLen
                )
            }
        }
        guard status == kCCSuccess, outLen == kCCBlockSizeAES128 else {
            throw AESError.cryptorFailed(status)
        }
        return Data(out)
    }

    /// Standard CFB-128 (no OpenPGP prefix/resync) through ONE CommonCrypto
    /// cryptor: a single key schedule, output written straight into the
    /// caller's buffer. `CFBStream` keeps the cryptor across `update` calls,
    /// so non-contiguous input pieces encrypt as one continuous stream.
    struct CFBStream: ~Copyable {
        private let cryptor: CCCryptorRef

        /// `iv` must be 16 bytes; nil means the all-zero IV (OpenPGP SED).
        init(_ op: CCOperation, key: Data, iv: Data? = nil) throws {
            switch key.count {
            case kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256: break
            default: throw AESError.badKeyLength
            }
            var ivBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
            if let iv {
                guard iv.count == kCCBlockSizeAES128 else { throw AESError.badBlockLength }
                ivBytes = Array(iv)
            }
            var ref: CCCryptorRef?
            let status = key.withUnsafeBytes { kptr in
                CCCryptorCreateWithMode(
                    op, CCMode(kCCModeCFB), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                    ivBytes, kptr.baseAddress, key.count,
                    nil, 0, 0, CCModeOptions(0), &ref
                )
            }
            guard status == kCCSuccess, let ref else { throw AESError.cryptorFailed(status) }
            cryptor = ref
        }

        deinit { CCCryptorRelease(cryptor) }

        /// Transforms `input` into `output` (same length; CFB is a stream
        /// mode, so any length works and the keystream position carries
        /// over to the next call).
        func update(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer) throws {
            guard input.count <= output.count else { throw AESError.badBlockLength }
            guard let src = input.baseAddress, let dst = output.baseAddress else { return }
            var moved = 0
            let status = CCCryptorUpdate(cryptor, src, input.count, dst, output.count, &moved)
            guard status == kCCSuccess, moved == input.count else { throw AESError.cryptorFailed(status) }
        }
    }

    /// One-shot CFB-128 over `input` into a fresh buffer of the same size.
    static func cfb(_ op: CCOperation, _ input: Data, key: Data, iv: Data?) throws -> Data {
        let stream = try CFBStream(op, key: key, iv: iv)
        var out = Data(count: input.count)
        try input.withUnsafeBytes { src in
            try out.withUnsafeMutableBytes { dst in try stream.update(src, into: dst) }
        }
        return out
    }

    /// Plain CFB decrypt (NO prefix/resync): FR starts at `iv`, standard CFB.
    /// Proton secret keys encrypt MPI+checksum this way (empirically: secretData
    /// is exactly MPI + SHA-1 with no random prefix on current key packets).
    static func cfbDecrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard iv.count == kCCBlockSizeAES128 else { throw AESError.badBlockLength }
        return try cfb(CCOperation(kCCDecrypt), ciphertext, key: key, iv: iv)
    }

    /// Plain CFB encrypt (NO prefix/resync): FR starts at `iv`, standard CFB.
    /// Exact inverse of cfbDecrypt (used to lock generated secret keys).
    static func cfbEncrypt(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard iv.count == kCCBlockSizeAES128 else { throw AESError.badBlockLength }
        return try cfb(CCOperation(kCCEncrypt), plaintext, key: key, iv: iv)
    }
}

enum PGPSymmetricAlgo {
    static func keyLength(id: UInt8) throws -> Int {
        switch id {
        case 7: return 16 // AES-128
        case 8: return 24 // AES-192
        case 9: return 32 // AES-256
        default: throw AESError.badKeyLength
        }
    }
}
