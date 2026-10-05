// Nucleon Transfer — release micro-benchmarks for Core hot paths (F8.3-B0).
// Each case runs a warm-up, then N timed iterations; the median (and min)
// are printed. Inputs are synthetic and offline (throwaway keys, fake
// queue store/folder creator) — no network, no secrets.
// Usage: swift run -c release --package-path Benchmarks nucleon-bench [filter]
import CryptoKit
import Foundation
import Synchronization

@testable import NucleonCore

/// Keeps results alive so the optimizer cannot drop the measured work.
@inline(never)
func blackHole<T>(_ value: T) {
    withExtendedLifetime(value) {}
}

struct BenchCase {
    var name: String
    var runs: Int
    /// Bytes processed per run (prints MB/s when non-zero).
    var bytes: Int = 0
    var body: () async throws -> Void
}

struct BenchResult {
    var median: Duration
    var min: Duration
}

nonisolated(nonsending) func measure(_ c: BenchCase) async throws -> BenchResult {
    try await c.body() // warm-up
    var samples: [Duration] = []
    samples.reserveCapacity(c.runs)
    let clock = ContinuousClock()
    for _ in 0..<c.runs {
        let start = clock.now
        try await c.body()
        samples.append(clock.now - start)
    }
    samples.sort()
    return BenchResult(median: samples[samples.count / 2], min: samples[0])
}

func milliseconds(_ d: Duration) -> Double {
    let (s, attos) = d.components
    return Double(s) * 1_000 + Double(attos) / 1e15
}

// MARK: - fakes

/// In-memory queue snapshot store (counts bytes written).
final class MemoryQueueStore: TransferQueueStore {
    private let written = Mutex<Int>(0)
    func read() -> Data? { nil }
    func write(_ data: Data) throws { written.withLock { $0 += data.count } }
    func backup() {}
}

/// Remote folder creator that answers instantly with a derived LinkID.
struct InstantFolders: RemoteFolderCreator {
    func ensureFolder(name: String, parentLinkID: String, shareID: String) async throws -> String {
        parentLinkID + "/" + name
    }
}

// MARK: - inputs

let mib4 = 4 * 1024 * 1024

func randomData(_ count: Int) -> Data {
    var g = SystemRandomNumberGenerator()
    var d = Data(count: count)
    d.withUnsafeMutableBytes { raw in
        let words = raw.bindMemory(to: UInt64.self)
        for i in words.indices { words[i] = g.next() }
    }
    return d
}

/// 10 top folders x 10 subfolders x 30 files = 3 000 files, 110 folders.
func syntheticTree() -> [LocalTreeScan.Entry] {
    let root = URL(fileURLWithPath: "/tmp/nucleon-bench-tree")
    var out = [LocalTreeScan.Entry(url: root, relativePath: "", isDirectory: true, size: 0)]
    for a in 0..<10 {
        let ra = "dir-\(a)"
        out.append(.init(url: root.appendingPathComponent(ra), relativePath: ra, isDirectory: true, size: 0))
        for b in 0..<10 {
            let rb = "\(ra)/sub-\(b)"
            out.append(.init(url: root.appendingPathComponent(rb), relativePath: rb, isDirectory: true, size: 0))
            for f in 0..<30 {
                let rf = "\(rb)/file-\(f).bin"
                out.append(.init(url: root.appendingPathComponent(rf), relativePath: rf, isDirectory: false, size: 1024))
            }
        }
    }
    return out
}

func syntheticItems(_ n: Int) -> [DriveItem] {
    (0..<n).map { i in
        DriveItem(
            id: "L\(i)", shareID: "S", parentLinkID: "P",
            name: "Report \(Int.random(in: 0..<100_000)) – draft \(i).pdf",
            isNameDecrypted: true,
            kind: i % 7 == 0 ? .folder : .file,
            size: Int64(i * 37), modified: Date(timeIntervalSince1970: Double(i)),
            mimeType: "application/pdf"
        )
    }
}

// MARK: - cases

func makeCases() throws -> [BenchCase] {
    var cases: [BenchCase] = []

    // FileUpload block encrypt/decrypt (literal + SEIPDv1 + MDC, AES-256).
    let contentKey = randomData(FileUpload.sessionKeyLength)
    let block = randomData(mib4)
    let encrypted = try FileUpload.encryptBlock(block, contentKey: contentKey)
    cases.append(BenchCase(name: "upload.encryptBlock.4MiB", runs: 15, bytes: mib4) {
        blackHole(try FileUpload.encryptBlock(block, contentKey: contentKey))
    })
    cases.append(BenchCase(name: "upload.decryptBlock.4MiB", runs: 15, bytes: mib4) {
        blackHole(try FileUpload.decryptBlock(encrypted, contentKey: contentKey))
    })

    // Armored message decrypt (PKESK ECDH + SEIPDv1) of 4 MiB.
    let priv = Curve25519.KeyAgreement.PrivateKey()
    let fp = Data((0..<20).map { UInt8($0) })
    let oid = Data([0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x00])
    let recipient = EncryptRecipient(publicPoint: priv.publicKey.rawRepresentation, fingerprint: fp,
                                     curveOIDBody: oid, kdfHash: 8, kdfCipher: 9)
    let candidate = DecryptCandidate(scalarLE: priv.rawRepresentation, fingerprint: fp,
                                     kdfHash: 8, kdfCipher: 9, curveOIDBody: oid)
    let armored = try MessageEncrypt.encrypt(plaintext: block, recipient: recipient)
    cases.append(BenchCase(name: "message.decrypt.4MiB", runs: 15, bytes: mib4) {
        blackHole(try MessageDecrypt.decrypt(armored: armored, candidates: [candidate]))
    })

    // SRP-sized modular exponentiation (2048-bit base, exponent, modulus).
    var modBytes = randomData(256)
    modBytes[modBytes.startIndex] |= 1 // odd (LE low byte)
    modBytes[modBytes.index(before: modBytes.endIndex)] |= 0x80 // full 2048 bits
    let mod = BigUInt(dataLE: modBytes)
    let base = BigUInt(dataLE: randomData(255))
    let exp = BigUInt(dataLE: randomData(256))
    cases.append(BenchCase(name: "bigint.modPow.2048", runs: 7) {
        blackHole(BigUInt.modPow(base, exp, mod))
    })

    // bcrypt cost 10 (Proton login password hash).
    let hasher = ProtonBcryptHasher()
    cases.append(BenchCase(name: "bcrypt.cost10", runs: 7) {
        blackHole(try hasher.hash(password: Data("correct horse battery".utf8),
                                  dotSlashSalt: "$2y$10$abcdefghijklmnopqrstuu"))
    })

    // TransferQueue.enqueueTree of 3k files (instant folder creator).
    let tree = syntheticTree()
    cases.append(BenchCase(name: "queue.enqueueTree.3k", runs: 9) {
        let q = TransferQueue(store: MemoryQueueStore())
        let ids = try await q.enqueueTree(
            entries: tree, shareID: "S", rootParentLinkID: "ROOT", folders: InstantFolders()
        )
        blackHole(ids)
    })

    // Browser visibleItems equivalent: filter + localized sort, folders first.
    let comparators = [KeyPathComparator(\DriveItem.name, comparator: .localizedStandard)]
    for n in [500, 5_000] {
        let items = syntheticItems(n)
        cases.append(BenchCase(name: "ordering.filterSort.\(n)", runs: 15) {
            blackHole(DriveItemOrdering.sorted(DriveItemOrdering.filtered(items, query: "draft"),
                                               using: comparators))
        })
    }
    return cases
}

@main
struct NucleonBench {
    static func main() async throws {
        let filter = CommandLine.arguments.dropFirst().first
        let cases = try makeCases().filter { c in filter.map { c.name.contains($0) } ?? true }
        guard !cases.isEmpty else {
            print("no benchmark matches \(filter ?? "")")
            return
        }
        print("benchmark".padding(toLength: 28, withPad: " ", startingAt: 0)
              + "  median ms      min ms   runs  throughput")
        for c in cases {
            let r = try await measure(c)
            let med = milliseconds(r.median)
            var line = c.name.padding(toLength: 28, withPad: " ", startingAt: 0)
            line += String(format: "  %9.2f  %10.2f  %5d", med, milliseconds(r.min), c.runs)
            if c.bytes > 0, med > 0 {
                line += String(format: "  %7.1f MB/s", Double(c.bytes) / 1_000_000 / (med / 1_000))
            }
            print(line)
        }
    }
}
