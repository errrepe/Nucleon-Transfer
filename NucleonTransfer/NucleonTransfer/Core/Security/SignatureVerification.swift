// Nucleon Transfer — signature verification policy (F8.1-S2).
// One place decides WHO may sign WHAT and turns a PGP check into an
// outcome. Callers pick the severity:
//   - key-level material (share/node passphrase, address-key Token,
//     NodeHashKey) fails CLOSED via `DecryptChain.require` → throws;
//   - content-level integrity (names, content key, manifest, blocks)
//     surfaces as `DriveItem.signatureIssue` or a download error.
// Signer selection mirrors the official C# SDK
// (ProtonDriveApps/sdk client/cs/src/Proton.Drive.Sdk/Nodes/AuthorshipClaim.cs
// `CreateAsync` + `GetKeyRing(anonymousFallbackKey)`): a claimed signature
// email resolves to that address's keys; an empty email ("anonymous")
// falls back to a node/parent key. Only the user's OWN addresses are
// resolvable here (Proton-API-Bridge drive.go
// `getSignatureVerificationKeyring` parity — no /core/v4/keys lookup), so a
// foreign signer yields `.noVerifier`.
import Foundation

enum SignatureVerification {
    /// Result of one signature check (never thrown — callers decide).
    enum Outcome: Equatable, Sendable {
        case valid
        /// No signature field / no signature packet.
        case missing
        /// Present but does not verify with any allowed signer.
        case invalid
        /// Signature uses MD5/SHA-1/… (`SigError.weakHash`, F8.1-S3).
        case weakHash(UInt8)
        /// The claimed signer is not one of the user's addresses (shared
        /// content) — cannot be checked without fetching public keys.
        case noVerifier

        var isValid: Bool { self == .valid }
    }

    // MARK: - signer selection

    /// Ed25519 points allowed to sign for `claimedEmail`.
    /// - nil/empty email → `anonymousFallback` (C# SDK AuthorshipClaim).
    /// - email of one of the user's addresses (case-insensitive) → that
    ///   address's #22 points.
    /// - address keys without any email (legacy callers/tests) → all
    ///   address points (pre-S2 behaviour).
    /// - otherwise → [] (foreign signer → `.noVerifier`).
    static func signerPoints(
        claimedEmail: String?,
        addressKeys: [KeyringCache.UnlockedKey],
        anonymousFallback: [Data]
    ) -> [Data] {
        guard let email = claimedEmail?.trimmingCharacters(in: .whitespaces), !email.isEmpty else {
            return anonymousFallback
        }
        guard addressKeys.contains(where: { $0.email != nil }) else {
            return DecryptChain.edPoints(addressKeys)
        }
        let wanted = email.lowercased()
        return DecryptChain.edPoints(addressKeys.filter { $0.email?.lowercased() == wanted })
    }

    // MARK: - detached signatures

    /// Verifies an armored detached signature over ANY of `dataVariants`
    /// (several accepted inputs only where documented legacy variants
    /// exist, e.g. Nucleon-uploaded content keys) with ANY signer point.
    static func detached(
        armored: String?,
        over dataVariants: [Data],
        signerPoints: [Data]
    ) -> Outcome {
        guard let armored, !armored.isEmpty else { return .missing }
        guard let raw = try? Armor.decode(armored),
              let packets = try? PGPPackets.parse(raw) else {
            return .invalid
        }
        return check(
            signatureBodies: packets.filter { $0.tag == 2 }.map(\.body),
            over: dataVariants, signerPoints: signerPoints
        )
    }

    /// Core check over parsed signature-packet bodies.
    static func check(
        signatureBodies: [Data],
        over dataVariants: [Data],
        signerPoints: [Data]
    ) -> Outcome {
        guard !signatureBodies.isEmpty else { return .missing }
        guard !signerPoints.isEmpty else { return .noVerifier }
        var weak: UInt8? = nil
        for body in signatureBodies {
            guard let sig = try? DetachedSig.parse(body: body) else { continue }
            for data in dataVariants {
                for point in signerPoints {
                    do {
                        if try sig.verify(data: data, signerPointMPI: point) { return .valid }
                    } catch SigError.weakHash(let algo) {
                        weak = algo
                    } catch {
                        continue
                    }
                }
            }
        }
        if let weak { return .weakHash(weak) }
        return .invalid
    }

    // MARK: - inline (one-pass) signatures

    /// Splits a decrypted inner packet stream (OPS tag 4 + literal tag 11 +
    /// SIG tag 2, gopenpgp `KeyRing.Encrypt(plain, signingKR)` shape) into
    /// the literal payload and the outcome of its inline signature.
    static func inline(
        innerPackets: Data,
        signerPoints: [Data]
    ) throws -> (literal: Data, outcome: Outcome) {
        let literal = try SEDDecrypt.literalData(innerPackets)
        let sigs = try PGPPackets.parse(innerPackets).filter { $0.tag == 2 }.map(\.body)
        return (literal, check(signatureBodies: sigs, over: [literal], signerPoints: signerPoints))
    }

    /// Decrypts an armored message and checks its inline signature.
    static func decryptInline(
        armored: String,
        candidates: [DecryptCandidate],
        signerPoints: [Data]
    ) throws -> (literal: Data, outcome: Outcome) {
        let inner = try MessageDecrypt.decryptPackets(armored: armored, candidates: candidates)
        return try inline(innerPackets: inner, signerPoints: signerPoints)
    }
}
