// Nucleon Transfer — checked CSPRNG bytes (F8.1-S1).
// SecRandomCopyBytes can fail; its status is always checked and a failure
// throws instead of silently leaving zeroed (predictable) bytes behind.
import Foundation
import Security

enum SecureRandom {
    static func bytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(count: count)
        let status = out.withUnsafeMutableBytes { buf -> OSStatus in
            guard let base = buf.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw ProtonAPIError.secureRandomFailed }
        return out
    }
}
