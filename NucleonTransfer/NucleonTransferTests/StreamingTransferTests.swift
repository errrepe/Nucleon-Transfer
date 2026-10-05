// Nucleon Transfer — streaming upload/download pipeline tests (F8.3-P2).
// Upload: StreamingUpload against a fake Drive API (draft, per-batch block
// links, storage POSTs, commit) — same manifest/XAttr as the whole-file
// path, bounded block buffers, monotonic per-block progress, cancellation
// discards the draft, upstream signature forms. Download:
// FileDownload.downloadToPart with a fake block fetch — out-of-order
// arrival, bounded window, legacy signatures, part file removed on
// failure/cancellation. Plus MPI.read on slices and armor CRC24.

import CryptoKit
import Foundation
import Testing

@testable import NucleonTransfer

// MARK: - fixtures

private struct Keys {
    let parentKeys: [KeyringCache.UnlockedKey]
    let addressKeys: [KeyringCache.UnlockedKey]
    let addressPoint: Data
    let parentHashKey = Data((0..<32).map { UInt8($0 &+ 1) })

    init() throws {
        let parentX = Curve25519.KeyAgreement.PrivateKey()
        let addr = Curve25519.Signing.PrivateKey()
        parentKeys = [KeyringCache.UnlockedKey(
            keyID: "test-parent#18", algo: 18, seed: parentX.rawRepresentation,
            fingerprint: Data(repeating: 0x55, count: 20), kdfHash: 8, kdfCipher: 7,
            curveOIDBody: NodeKeyGen.ecdhOID
        )]
        addressKeys = [KeyringCache.UnlockedKey(
            keyID: "test-addr#22", algo: 22, seed: addr.rawRepresentation,
            fingerprint: Data(repeating: 0x66, count: 20), kdfHash: 8, kdfCipher: 9,
            curveOIDBody: NodeKeyGen.edOID
        )]
        addressPoint = addr.publicKey.rawRepresentation
    }
}

private func randomBytes(_ n: Int) -> Data {
    Data((0..<n).map { _ in UInt8.random(in: .min ... .max) })
}

private func signatureBody(_ armored: String) throws -> Data {
    try #require(try PGPPackets.parse(try Armor.decode(armored)).first(where: { $0.tag == 2 }).map(\.body))
}

/// Records what the pipeline sends; counts block buffers between their
/// link request and their storage POST (the pipeline's resident blocks).
private actor FakeUploadAPI: FileUploadAPI {
    var draftRequest: CreateFileRequest?
    var batches: [[BlockUploadEntry]] = []
    var stored: [Int: Data] = [:]
    var commit: CommitRevisionRequest?
    var deleted: [String] = []
    var outstanding = 0
    var maxOutstanding = 0
    var uploads = 0
    /// Called after each storage POST with the running count.
    var afterUpload: (@Sendable (Int) async -> Void)?
    var failUploadAt: Int?

    func setAfterUpload(_ hook: @escaping @Sendable (Int) async -> Void) { afterUpload = hook }
    func setFailUploadAt(_ n: Int) { failUploadAt = n }

    func checkAvailableHashes(
        shareID: String, parentLinkID: String, hashes: [String]
    ) async throws -> (available: [String], pending: [PendingHash]) {
        (hashes, [])
    }

    func createFileDraft(shareID: String, request: CreateFileRequest) async throws -> (linkID: String, revisionID: String) {
        draftRequest = request
        return ("L1", "R1")
    }

    func deleteDraft(shareID: String, parentLinkID: String, linkID: String) async throws {
        deleted.append(linkID)
    }

    func requestBlockUploads(
        addressID: String, shareID: String, linkID: String,
        revisionID: String, entries: [BlockUploadEntry]
    ) async throws -> [StorageUploadLink] {
        batches.append(entries)
        outstanding += entries.count
        maxOutstanding = max(maxOutstanding, outstanding)
        return entries.map {
            StorageUploadLink(bareURL: "https://storage.test/\($0.index)", token: "T\($0.index)", url: "", index: $0.index)
        }
    }

    func uploadBlockBytes(bareURL: String, token: String, bytes: Data) async throws {
        uploads += 1
        if let failUploadAt, uploads == failUploadAt { throw URLError(.networkConnectionLost) }
        let index = Int(bareURL.split(separator: "/").last ?? "") ?? -1
        stored[index] = bytes
        outstanding -= 1
        await afterUpload?(uploads)
    }

    func commitRevision(
        shareID: String, linkID: String, revisionID: String, request: CommitRevisionRequest
    ) async throws -> CommitRevisionResponse {
        commit = request
        return try JSONDecoder().decode(CommitRevisionResponse.self, from: Data(#"{"Code":1000}"#.utf8))
    }

    func isRevisionCommitted(
        shareID: String, linkID: String, revisionID: String, parentLinkID: String?
    ) async throws -> Bool { false }
}

/// Delays the first block of every batch so later blocks finish encoding
/// first (exercises the in-order SHA-1 feed).
private struct SlowFirstBlockSource: UploadBlockSource {
    let data: Data
    let blockSize: Int
    let window: Int
    var size: Int64 { Int64(data.count) }

    func read(offset: Int64, count: Int) throws -> Data {
        let index = Int(offset) / blockSize
        if window > 1, index % window == 0, count > 0 { usleep(20_000) }
        return try DataBlockSource(data: data).read(offset: offset, count: count)
    }
}

private actor Recorder<T: Sendable> {
    var values: [T] = []
    func add(_ v: T) { values.append(v) }
}

private actor TaskBox {
    var task: Task<Void, Never>?
    func set(_ t: Task<Void, Never>) { task = t }
    func cancel() { task?.cancel() }
}

// MARK: - upload

@Suite struct StreamingUploadTests {
    @Test func streamedUploadMatchesTheWholeFilePath() async throws {
        let keys = try Keys()
        let blockSize = 4096
        let data = randomBytes(blockSize * 3 + blockSize / 2) // 3.5 blocks
        let node = try FolderCreate.generateNode()
        let contentKey = randomBytes(32)
        let mtime = Date(timeIntervalSince1970: 1_700_000_000)
        let whole = try FileUpload.prepareUpload(
            fileName: "doc.bin", parentLinkID: "P", data: data, modificationTime: mtime,
            blockSize: blockSize, parentKeys: keys.parentKeys,
            parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
            node: node, contentKey: contentKey
        )
        let api = FakeUploadAPI()
        let result = try await StreamingUpload.run(
            api: api, shareID: "S", parentLinkID: "P", fileName: "doc.bin",
            source: DataBlockSource(data: data), parentKeys: keys.parentKeys,
            parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
            addressID: "A", blockSize: blockSize, window: 2, modificationTime: mtime,
            node: node, contentKey: contentKey
        )
        #expect(result.linkID == "L1" && result.revisionID == "R1")
        let entries = await api.batches.flatMap { $0 }
        // Same block layout as the whole-file path: indices, wire sizes.
        #expect(entries.map(\.index) == whole.blocks.map(\.index))
        #expect(entries.map(\.size) == whole.blocks.map(\.encrypted.count))
        let stored = await api.stored
        var hashes: [Data] = []
        var plain = Data()
        for entry in entries {
            let bytes = try #require(stored[entry.index])
            let hash = Data(SHA256.hash(data: bytes))
            #expect(entry.hash == hash.base64EncodedString())
            hashes.append(hash)
            plain.append(try FileUpload.decryptBlock(bytes, contentKey: contentKey))
        }
        #expect(plain == data)
        // Manifest: address signature over the ordered raw hashes.
        let commit = try #require(await api.commit)
        #expect(try DetachedSig.parse(body: signatureBody(commit.manifestSignature))
            .verify(data: FileUpload.manifestInput(hashes: hashes), signerPointMPI: keys.addressPoint))
        // XAttr: byte-identical JSON to the whole-file path (sizes, mtime,
        // MIME and BlockSizes are deterministic).
        let nodeCands = node.keys.compactMap(\.candidate)
        let streamedXAttr = try MessageDecrypt.decrypt(armored: commit.xAttr, candidates: nodeCands)
        #expect(String(decoding: streamedXAttr, as: UTF8.self) == String(decoding: whole.xAttrJSON, as: UTF8.self))
        let xattr = try JSONDecoder().decode(FileXAttr.self, from: whole.xAttrJSON)
        #expect(xattr.common.blockSizes == [4096, 4096, 4096, 2048])
        #expect(xattr.common.size == Int64(data.count))
        // Digests.SHA1 (F8.3-P6): whole-plaintext SHA-1, lowercase hex.
        #expect(xattr.common.digests == FileXAttrDigests(sha1: Data(Insecure.SHA1.hash(data: data))))
    }

    /// The streamed SHA-1 must be over the plaintext in FILE order even when
    /// a batch's blocks finish encoding out of order (block 1 of every batch
    /// is read slowest here), for several windows and an empty file.
    @Test func xAttrSHA1CoversThePlaintextInOrder() async throws {
        let keys = try Keys()
        let blockSize = 1024
        for (length, window) in [(blockSize * 9 + 77, 4), (blockSize * 5, 2), (blockSize * 3 + 1, 1), (100, 4), (0, 3)] {
            let data = randomBytes(length)
            let api = FakeUploadAPI()
            let result = try await StreamingUpload.run(
                api: api, shareID: "S", parentLinkID: "P", fileName: "x.bin",
                source: SlowFirstBlockSource(data: data, blockSize: blockSize, window: window),
                parentKeys: keys.parentKeys, parentHashKey: keys.parentHashKey,
                addressKeys: keys.addressKeys, addressID: "A",
                blockSize: blockSize, window: window
            )
            let commit = try #require(await api.commit)
            let json = try MessageDecrypt.decrypt(
                armored: commit.xAttr, candidates: result.node.keys.compactMap(\.candidate)
            )
            let dict = try #require(JSONSerialization.jsonObject(with: Data(json)) as? [String: Any])
            let common = try #require(dict["Common"] as? [String: Any])
            let digests = try #require(common["Digests"] as? [String: Any])
            let expected = Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined()
            #expect(digests as? [String: String] == ["SHA1": expected], "length \(length) window \(window)")
            #expect(expected.count == 40)
        }
    }

    /// XAttr from builds before F8.3-P6 (no Digests) still decodes.
    @Test func xAttrWithoutDigestsStillDecodes() throws {
        let legacy = Data(#"{"Common":{"BlockSizes":[26],"MIMEType":"text/plain","ModificationTime":"2023-11-14T22:13:20Z","Size":26}}"#.utf8)
        let xattr = try JSONDecoder().decode(FileXAttr.self, from: legacy)
        #expect(xattr.common.digests == nil)
        #expect(xattr.common.blockSizes == [26])
    }

    @Test func uploadSignaturesUseTheUpstreamFormOnly() async throws {
        let keys = try Keys()
        let data = randomBytes(5000)
        let api = FakeUploadAPI()
        let result = try await StreamingUpload.run(
            api: api, shareID: "S", parentLinkID: "P", fileName: "a.bin",
            source: DataBlockSource(data: data), parentKeys: keys.parentKeys,
            parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
            addressID: "A", blockSize: 4096
        )
        let request = try #require(await api.draftRequest)
        let nodeCands = result.node.keys.compactMap(\.candidate)
        let nodePoint = try Curve25519.Signing.PrivateKey(rawRepresentation: result.node.generated.edSeed)
            .publicKey.rawRepresentation
        // Content key: node signature over the SESSION KEY, not the packet.
        let (_, sessionKey) = try FileUpload.openContentKey(request.contentKeyPacket, nodeCandidates: nodeCands)
        let ckpRaw = try #require(Data(base64Encoded: request.contentKeyPacket))
        #expect(SignatureVerification.detached(
            armored: request.contentKeyPacketSignature, over: [sessionKey], signerPoints: [nodePoint]
        ) == .valid)
        #expect(SignatureVerification.detached(
            armored: request.contentKeyPacketSignature, over: [ckpRaw], signerPoints: [nodePoint]
        ) == .invalid)
        // Blocks: address signature over the PLAINTEXT, not the hash.
        let entries = await api.batches.flatMap { $0 }
        let stored = await api.stored
        #expect(entries.count == 2)
        for entry in entries {
            let bytes = try #require(stored[entry.index])
            let plaintext = try FileUpload.decryptBlock(bytes, contentKey: sessionKey)
            let sigPacket = try MessageDecrypt.decrypt(armored: entry.encSignature, candidates: nodeCands)
            let bodies = try PGPPackets.parse(sigPacket).filter { $0.tag == 2 }.map(\.body)
            #expect(SignatureVerification.check(
                signatureBodies: bodies, over: [plaintext], signerPoints: [keys.addressPoint]
            ) == .valid)
            #expect(SignatureVerification.check(
                signatureBodies: bodies, over: [Data(SHA256.hash(data: bytes))], signerPoints: [keys.addressPoint]
            ) == .invalid)
            // ...and the download side accepts it.
            try FileDownload.verifyBlockSignature(
                entry.encSignature, index: entry.index, plaintext: plaintext,
                encryptedHash: Data(SHA256.hash(data: bytes)),
                check: .init(nodeCandidates: nodeCands, signerPoints: [keys.addressPoint])
            )
        }
    }

    @Test func blockBuffersStayWithinTheWindowAndProgressIsMonotonic() async throws {
        let keys = try Keys()
        let blockSize = 1024
        let data = randomBytes(blockSize * 7 + 300) // 8 blocks
        let api = FakeUploadAPI()
        let progress = Recorder<Int64>()
        _ = try await StreamingUpload.run(
            api: api, shareID: "S", parentLinkID: "P", fileName: "p.bin",
            source: DataBlockSource(data: data), parentKeys: keys.parentKeys,
            parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
            addressID: "A", blockSize: blockSize, window: 3,
            progress: { await progress.add($0) }
        )
        #expect(await api.maxOutstanding <= 3)
        #expect(await api.batches.map(\.count) == [3, 3, 2])
        let values = await progress.values
        #expect(values.count == 8)
        #expect(zip(values, values.dropFirst()).allSatisfy { $0 < $1 })
        #expect(values.last == Int64(data.count))
    }

    @Test func cancellationMidFileStopsAndDiscardsTheDraft() async throws {
        let keys = try Keys()
        let blockSize = 1024
        let data = randomBytes(blockSize * 10)
        let api = FakeUploadAPI()
        let box = TaskBox()
        await api.setAfterUpload { n in if n == 2 { await box.cancel() } }
        let outcome = Recorder<String>()
        let task = Task {
            do {
                _ = try await StreamingUpload.run(
                    api: api, shareID: "S", parentLinkID: "P", fileName: "c.bin",
                    source: DataBlockSource(data: data), parentKeys: keys.parentKeys,
                    parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
                    addressID: "A", blockSize: blockSize, window: 2
                )
                await outcome.add("finished")
            } catch is CancellationError {
                await outcome.add("cancelled")
            } catch {
                await outcome.add("error \(error)")
            }
        }
        await box.set(task)
        await task.value
        #expect(await outcome.values == ["cancelled"])
        #expect(await api.deleted == ["L1"])
        #expect(await api.commit == nil)
        #expect(await api.uploads < 10)
    }

    @Test func failedBlockDiscardsTheDraftAndSurfacesTheError() async throws {
        let keys = try Keys()
        let api = FakeUploadAPI()
        await api.setFailUploadAt(3)
        await #expect(throws: URLError.self) {
            _ = try await StreamingUpload.run(
                api: api, shareID: "S", parentLinkID: "P", fileName: "f.bin",
                source: DataBlockSource(data: randomBytes(5000)), parentKeys: keys.parentKeys,
                parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
                addressID: "A", blockSize: 1024, window: 2
            )
        }
        #expect(await api.deleted == ["L1"])
        #expect(await api.commit == nil)
    }

    @Test func emptyFileCommitsWithoutBlocks() async throws {
        let keys = try Keys()
        let api = FakeUploadAPI()
        _ = try await StreamingUpload.run(
            api: api, shareID: "S", parentLinkID: "P", fileName: "empty.txt",
            source: DataBlockSource(data: Data()), parentKeys: keys.parentKeys,
            parentHashKey: keys.parentHashKey, addressKeys: keys.addressKeys,
            addressID: "A"
        )
        #expect(await api.batches.isEmpty)
        let commit = try #require(await api.commit)
        #expect(try DetachedSig.parse(body: signatureBody(commit.manifestSignature))
            .verify(data: Data(), signerPointMPI: keys.addressPoint))
    }

    @Test func fileSourceReadsBlocksAndDetectsTruncation() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nt-src-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("f.bin")
        let data = randomBytes(10_000)
        try data.write(to: url)
        let source = try FileBlockSource(url: url)
        #expect(source.size == 10_000)
        #expect(try source.read(offset: 4096, count: 4096) == data[4096..<8192])
        #expect(try source.read(offset: 8192, count: 1808) == data[8192...])
        // The file shrank after it was opened: the read fails, never pads.
        try Data(count: 5000).write(to: url)
        #expect(throws: UploadSourceError.truncated) {
            _ = try source.read(offset: 8192, count: 1808)
        }
        #expect(throws: UploadSourceError.self) {
            _ = try FileBlockSource(url: dir.appendingPathComponent("missing"))
        }
    }
}

// MARK: - download

private struct EncodedFile {
    let data: Data
    let contentKey: Data
    let blocks: [RevisionBlock]
    let storage: [Int: Data]
    let check: FileDownload.BlockSignatureCheck
}

/// Encrypts `data` into blocks like an upload would; `legacy` signs the
/// encrypted-block hash (F4.3 builds) instead of the plaintext.
private func encodeFile(_ data: Data, blockSize: Int, legacy: Bool = false) throws -> EncodedFile {
    let keys = try Keys()
    let prepared = try FileUpload.prepareUpload(
        fileName: "x.bin", parentLinkID: "P", data: data, blockSize: blockSize,
        parentKeys: keys.parentKeys, parentHashKey: keys.parentHashKey,
        addressKeys: keys.addressKeys
    )
    let nodeRecipient = try #require(prepared.node.ecdhRecipient)
    let signer = try FileUpload.Signer(addressKeys: keys.addressKeys)
    var blocks: [RevisionBlock] = []
    var storage: [Int: Data] = [:]
    for b in prepared.blocks {
        var encSig = b.encSignature
        if legacy {
            let packet = try FileUpload.blockSignaturePacket(
                blockHash: b.hash, signerSeedLE: signer.seed,
                signerKeyID: signer.keyID, signerFingerprint: signer.fingerprint
            )
            encSig = try FileUpload.encryptSignaturePacket(packet, nodeRecipient: nodeRecipient)
        }
        let json: [String: Any] = [
            "Index": b.index, "Hash": b.hash.base64EncodedString(),
            "Token": "T", "BareURL": "https://storage.test/\(b.index)", "EncSignature": encSig,
        ]
        blocks.append(try JSONDecoder().decode(
            RevisionBlock.self, from: JSONSerialization.data(withJSONObject: json)
        ))
        storage[b.index] = b.encrypted
    }
    return EncodedFile(
        data: data, contentKey: prepared.contentKey, blocks: blocks, storage: storage,
        check: .init(nodeCandidates: prepared.node.keys.compactMap(\.candidate), signerPoints: [keys.addressPoint])
    )
}

/// Tracks fetches started vs blocks written (the resident window).
private actor WindowProbe {
    var started = 0
    var written = 0
    var maxResident = 0
    func start() { started += 1; maxResident = max(maxResident, started - written) }
    func wrote(_ n: Int) { written = n }
}

private func tempDir() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("nt-stream-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

private func partFiles(in dir: URL) -> [String] {
    ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? [])
        .filter { $0.hasSuffix(FileDownload.partSuffix) }
}

@Suite struct StreamingDownloadTests {
    @Test func outOfOrderBlocksLandInOrderWithinTheWindow() async throws {
        let file = try encodeFile(randomBytes(1024 * 9 + 77), blockSize: 1024) // 10 blocks
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let probe = WindowProbe()
        let storage = file.storage
        let progress = Recorder<Int>()
        let result = try await FileDownload.downloadToPart(
            blocks: file.blocks.reversed(), contentKey: file.contentKey,
            signatures: file.check, window: 3, directory: dir, name: "x.bin",
            fetch: { block in
                await probe.start()
                // Earlier blocks answer LATER: arrival order is scrambled.
                try await Task.sleep(for: .milliseconds(3 * (10 - block.index % 4)))
                return try #require(storage[block.index])
            },
            progress: { done, _ in await probe.wrote(done); await progress.add(done) }
        )
        #expect(result.size == Int64(file.data.count))
        #expect(try Data(contentsOf: result.part) == file.data)
        #expect(await probe.maxResident <= 3)
        #expect(await progress.values == Array(1...10))
        // Finalize through the placement (exclusive move, reserved name).
        let placed = try await DownloadPlacement().place(
            part: result.part, in: dir, remoteName: "x.bin", fallback: "F", root: dir
        )
        #expect(placed.lastPathComponent == "x.bin")
        #expect(try Data(contentsOf: placed) == file.data)
        #expect(partFiles(in: dir).isEmpty)
    }

    @Test func legacySignedBlocksAreStillAccepted() async throws {
        let file = try encodeFile(randomBytes(3000), blockSize: 1024, legacy: true)
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let storage = file.storage
        let result = try await FileDownload.downloadToPart(
            blocks: file.blocks, contentKey: file.contentKey, signatures: file.check,
            window: 2, directory: dir, name: "legacy.bin",
            fetch: { try #require(storage[$0.index]) }
        )
        #expect(try Data(contentsOf: result.part) == file.data)
    }

    @Test func failingBlockRemovesThePartFile() async throws {
        let file = try encodeFile(randomBytes(5000), blockSize: 1024)
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        var storage = file.storage
        storage[3]?[0] ^= 0xFF // tampered storage bytes
        let tampered = storage
        await #expect(throws: FileDownloadError.hashMismatch(index: 3)) {
            _ = try await FileDownload.downloadToPart(
                blocks: file.blocks, contentKey: file.contentKey, signatures: file.check,
                window: 2, directory: dir, name: "bad.bin",
                fetch: { try #require(tampered[$0.index]) }
            )
        }
        #expect(partFiles(in: dir).isEmpty)
        // A wrong signer fails the block signature, part removed too.
        let wrongSigner = FileDownload.BlockSignatureCheck(
            nodeCandidates: file.check.nodeCandidates,
            signerPoints: [Curve25519.Signing.PrivateKey().publicKey.rawRepresentation]
        )
        let good = file.storage
        await #expect(throws: FileDownloadError.blockSignatureInvalid(index: 1)) {
            _ = try await FileDownload.downloadToPart(
                blocks: file.blocks, contentKey: file.contentKey, signatures: wrongSigner,
                window: 1, directory: dir, name: "bad.bin",
                fetch: { try #require(good[$0.index]) }
            )
        }
        #expect(partFiles(in: dir).isEmpty)
    }

    @Test func cancellationRemovesThePartFile() async throws {
        let file = try encodeFile(randomBytes(8000), blockSize: 1024)
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let storage = file.storage
        let task = Task {
            try await FileDownload.downloadToPart(
                blocks: file.blocks, contentKey: file.contentKey, signatures: file.check,
                window: 2, directory: dir, name: "slow.bin",
                fetch: { block in
                    if block.index > 2 { try await Task.sleep(for: .seconds(30)) }
                    return try #require(storage[block.index])
                }
            )
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(partFiles(in: dir).count == 1) // streaming into the part file
        task.cancel()
        await #expect(throws: CancellationError.self) { _ = try await task.value }
        #expect(partFiles(in: dir).isEmpty)
    }

    @Test func emptyRevisionYieldsAnEmptyPartFile() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let result = try await FileDownload.downloadToPart(
            blocks: [], contentKey: Data(count: 32), signatures: nil,
            window: 4, directory: dir, name: "empty",
            fetch: { _ in Data() }
        )
        #expect(result.size == 0)
        #expect(try Data(contentsOf: result.part).isEmpty)
    }

    @Test func blockIndexGapIsRejectedBeforeAnyFetch() async throws {
        let file = try encodeFile(randomBytes(3000), blockSize: 1024)
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        await #expect(throws: FileDownloadError.blockIndexGap) {
            _ = try await FileDownload.downloadToPart(
                blocks: [file.blocks[0], file.blocks[2]], contentKey: file.contentKey,
                signatures: nil, window: 2, directory: dir, name: "gap",
                fetch: { _ in Issue.record("fetched despite a gap"); return Data() }
            )
        }
        #expect(partFiles(in: dir).isEmpty)
    }
}

// MARK: - PGP helpers

@Suite struct F83P2CryptoHelperTests {
    @Test func mpiReadHonoursSliceOffsets() throws {
        // [junk x3] [bitlen 0x0009 → 2 bytes] [01 FF] [bitlen 8 → 1 byte] [7F]
        let backing = Data([0xAA, 0xBB, 0xCC, 0x00, 0x09, 0x01, 0xFF, 0x00, 0x08, 0x7F])
        let slice = backing[3...] // startIndex 3
        let (first, next) = try MPI.read(slice, from: 0)
        #expect(first == Data([0x01, 0xFF]))
        #expect(first.startIndex == 0)
        #expect(next == 4)
        let (second, end) = try MPI.read(slice, from: next)
        #expect(second == Data([0x7F]))
        #expect(end == slice.count)
        #expect(throws: SecretKeyError.self) { _ = try MPI.read(slice, from: end) }
        #expect(throws: SecretKeyError.self) { _ = try MPI.read(backing[3..<6], from: 0) }
    }

    @Test func armorDecodeChecksCRCWhenPresent() throws {
        let payload = randomBytes(300_000)
        let armored = Armor.encode(payload)
        #expect(try Armor.decode(armored) == payload)
        // CRLF line endings + armor headers are tolerated.
        let crlf = armored.replacingOccurrences(of: "\n", with: "\r\n")
            .replacingOccurrences(of: "-----\r\n\r\n", with: "-----\r\nVersion: test\r\n\r\n")
        #expect(try Armor.decode(crlf) == payload)
        // No CRC line: still accepted (optional per RFC 9580).
        let lines = armored.split(separator: "\n", omittingEmptySubsequences: false)
        let noCRC = lines.filter { !$0.hasPrefix("=") }.joined(separator: "\n")
        #expect(try Armor.decode(noCRC) == payload)
        // Wrong CRC → rejected.
        let badCRC = lines.map { $0.hasPrefix("=") ? "=AAAA" : String($0) }.joined(separator: "\n")
        #expect(throws: ArmorError.crcMismatch) { _ = try Armor.decode(badCRC) }
        #expect(throws: ArmorError.noBeginLine) { _ = try Armor.decode("no armor here") }
        // Known vector: CRC24 of "" is the init value 0xB704CE.
        #expect(Armor.crc24Bytes(Data()) == Data([0xB7, 0x04, 0xCE]))
    }
}
