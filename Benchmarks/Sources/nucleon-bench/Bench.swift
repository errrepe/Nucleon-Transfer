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
    /// Sample the live malloc heap while the case runs (F8.3-P2) and
    /// print the peak growth over the heap before each run.
    var sampleMemory = false
    var body: () async throws -> Void
}

struct BenchResult {
    var median: Duration
    var min: Duration
    /// Max over runs of (peak live heap during the run - heap before).
    var peakGrowth: UInt64?
}

/// Live malloc heap (bytes in use across all zones). Process footprint
/// is useless here: libmalloc keeps freed large blocks dirty, so after the
/// warm-up a whole-file run reuses them without the footprint moving.
func footprint() -> UInt64 {
    var stats = malloc_statistics_t()
    malloc_zone_statistics(nil, &stats)
    return UInt64(stats.size_in_use)
}

/// Polls `footprint()` every 0.5 ms on a dedicated thread until stopped.
final class PeakSampler: Sendable {
    private let peak = Mutex<UInt64>(0)
    private let running = Atomic<Bool>(true)

    func start() {
        peak.withLock { $0 = footprint() }
        Thread.detachNewThread { [self] in
            while running.load(ordering: .relaxed) {
                let now = footprint()
                peak.withLock { $0 = max($0, now) }
                usleep(500)
            }
        }
    }

    func stop() -> UInt64 {
        running.store(false, ordering: .relaxed)
        let now = footprint()
        return peak.withLock { max($0, now) }
    }
}

nonisolated(nonsending) func measure(_ c: BenchCase) async throws -> BenchResult {
    try await c.body() // warm-up
    var samples: [Duration] = []
    samples.reserveCapacity(c.runs)
    var peakGrowth: UInt64? = nil
    let clock = ContinuousClock()
    for _ in 0..<c.runs {
        let before = c.sampleMemory ? footprint() : 0
        let sampler = c.sampleMemory ? PeakSampler() : nil
        sampler?.start()
        let start = clock.now
        try await c.body()
        samples.append(clock.now - start)
        if let sampler {
            let peak = sampler.stop()
            peakGrowth = max(peakGrowth ?? 0, peak > before ? peak - before : 0)
        }
    }
    samples.sort()
    return BenchResult(median: samples[samples.count / 2], min: samples[0], peakGrowth: peakGrowth)
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

/// Drive API that answers instantly and drops block bytes (F8.3-P2
/// streaming upload benchmark — measures crypto + pipeline, no network).
actor NullUploadAPI: FileUploadAPI {
    private(set) var bytesUploaded = 0
    func checkAvailableHashes(
        shareID: String, parentLinkID: String, hashes: [String]
    ) async throws -> (available: [String], pending: [PendingHash]) { (hashes, []) }
    func createFileDraft(shareID: String, request: CreateFileRequest) async throws -> (linkID: String, revisionID: String) {
        ("L", "R")
    }
    func deleteDraft(shareID: String, parentLinkID: String, linkID: String) async throws {}
    func requestBlockUploads(
        addressID: String, shareID: String, linkID: String,
        revisionID: String, entries: [BlockUploadEntry]
    ) async throws -> [StorageUploadLink] {
        entries.map { StorageUploadLink(bareURL: "b", token: "t", url: "", index: $0.index) }
    }
    func uploadBlockBytes(bareURL: String, token: String, bytes: Data) async throws {
        // The real client builds a multipart body (one more copy).
        let body = FileUpload.multipartBlockBody(boundary: "bench", blockBytes: bytes)
        bytesUploaded += body.count
    }
    func commitRevision(
        shareID: String, linkID: String, revisionID: String, request: CommitRevisionRequest
    ) async throws -> CommitRevisionResponse {
        try JSONDecoder().decode(CommitRevisionResponse.self, from: Data(#"{"Code":1000}"#.utf8))
    }
    func isRevisionCommitted(
        shareID: String, linkID: String, revisionID: String, parentLinkID: String?
    ) async throws -> Bool { true }
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

    // F8.3-P2 whole-file vs streamed transfer of a 64 MiB file (fake
    // transport, real crypto + disk). "whole" replays the pre-P2 shape:
    // Data(contentsOf:) + every block encrypted/signed up front, then sent;
    // download: every encrypted block kept, reassembled, then written.
    let mib64 = 64 * 1024 * 1024
    let benchDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("nucleon-bench-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
    try FileManager.default.createDirectory(at: benchDir, withIntermediateDirectories: true)
    let bigFile = benchDir.appendingPathComponent("input.bin")
    try randomData(mib64).write(to: bigFile)
    let parentX = Curve25519.KeyAgreement.PrivateKey()
    let parentKeys = [KeyringCache.UnlockedKey(
        keyID: "bench-parent#18", algo: 18, seed: parentX.rawRepresentation,
        fingerprint: Data(repeating: 0x55, count: 20), kdfHash: 8, kdfCipher: 7,
        curveOIDBody: NodeKeyGen.ecdhOID
    )]
    let addrKey = Curve25519.Signing.PrivateKey()
    let addressKeys = [KeyringCache.UnlockedKey(
        keyID: "bench-addr#22", algo: 22, seed: addrKey.rawRepresentation,
        fingerprint: Data(repeating: 0x66, count: 20), kdfHash: 8, kdfCipher: 9,
        curveOIDBody: NodeKeyGen.edOID
    )]
    let hashKey = randomData(32)
    cases.append(BenchCase(name: "upload.whole.64MiB", runs: 5, bytes: mib64, sampleMemory: true) {
        let data = try Data(contentsOf: bigFile)
        let prepared = try FileUpload.prepareUpload(
            fileName: "input.bin", parentLinkID: "P", data: data,
            parentKeys: parentKeys, parentHashKey: hashKey, addressKeys: addressKeys
        )
        let api = NullUploadAPI()
        for block in prepared.blocks {
            try await api.uploadBlockBytes(bareURL: "b", token: "t", bytes: block.encrypted)
        }
        blackHole(prepared.blocks.count)
    })
    cases.append(BenchCase(name: "upload.stream.64MiB", runs: 5, bytes: mib64, sampleMemory: true) {
        let result = try await StreamingUpload.run(
            api: NullUploadAPI(), shareID: "S", parentLinkID: "P", fileName: "input.bin",
            source: FileBlockSource(url: bigFile), parentKeys: parentKeys,
            parentHashKey: hashKey, addressKeys: addressKeys, addressID: "A"
        )
        blackHole(result.linkID)
    })

    // Download inputs: the 64 MiB file encrypted into 16 blocks (storage).
    let encodedFile = try FileUpload.prepareUpload(
        fileName: "input.bin", parentLinkID: "P", data: Data(contentsOf: bigFile),
        parentKeys: parentKeys, parentHashKey: hashKey, addressKeys: addressKeys
    )
    let downloadKey = encodedFile.contentKey
    let storage = Dictionary(uniqueKeysWithValues: encodedFile.blocks.map { ($0.index, $0.encrypted) })
    let check = FileDownload.BlockSignatureCheck(
        nodeCandidates: encodedFile.node.keys.compactMap(\.candidate),
        signerPoints: [addrKey.publicKey.rawRepresentation]
    )
    let revisionBlocks: [RevisionBlock] = try encodedFile.blocks.map { b in
        let json: [String: Any] = [
            "Index": b.index, "Hash": b.hash.base64EncodedString(),
            "Token": "t", "BareURL": "b", "EncSignature": b.encSignature,
        ]
        return try JSONDecoder().decode(RevisionBlock.self, from: JSONSerialization.data(withJSONObject: json))
    }
    let encodedBlockCount = encodedFile.blocks.count
    blackHole(encodedBlockCount)
    let outDir = benchDir.appendingPathComponent("out", isDirectory: true)
    cases.append(BenchCase(name: "download.whole.64MiB", runs: 5, bytes: mib64, sampleMemory: true) {
        var fetched: [FileDownload.FetchedBlock] = []
        for b in revisionBlocks {
            // Fresh buffer per block, like a network response.
            let bytes = Data(storage[b.index] ?? Data())
            fetched.append(FileDownload.FetchedBlock(
                index: b.index, encrypted: bytes, expectedHashB64: b.hash, encSignature: b.encSignature
            ))
        }
        let data = try FileDownload.reassemble(blocks: fetched, contentKey: downloadKey, signatures: check)
        let url = try FileDownload.atomicWrite(data, to: outDir.appendingPathComponent("whole.bin"))
        try FileManager.default.removeItem(at: url)
    })
    cases.append(BenchCase(name: "download.stream.64MiB", runs: 5, bytes: mib64, sampleMemory: true) {
        let result = try await FileDownload.downloadToPart(
            blocks: revisionBlocks, contentKey: downloadKey, signatures: check,
            window: 4, directory: outDir, name: "stream.bin",
            fetch: { Data(storage[$0.index] ?? Data()) }
        )
        let url = try FileDownload.finalizePart(result.part, to: outDir.appendingPathComponent("stream.bin"))
        try FileManager.default.removeItem(at: url)
    })

    // Armor decode of a 4 MiB message (F8.3-P2 one-pass scan + table CRC).
    let armoredBlock = Armor.encode(block)
    cases.append(BenchCase(name: "armor.decode.4MiB", runs: 15, bytes: mib4) {
        blackHole(try Armor.decode(armoredBlock))
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
            if let peak = r.peakGrowth {
                line += String(format: "  peak heap +%.1f MiB", Double(peak) / 1_048_576)
            }
            print(line)
        }
    }
}
