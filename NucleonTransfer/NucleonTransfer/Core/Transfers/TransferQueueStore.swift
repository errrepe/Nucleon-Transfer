// Nucleon Transfer — upload queue persistence: store seam + snapshot codec (F8.2-R2).
// The queue snapshot is a versioned JSON envelope `{schemaVersion, jobs}`
// decoded job by job: one bad record (or a field a newer build added) drops
// only that record, never the whole queue. Whenever anything could not be
// decoded, the original file is copied to `<name>.bak` BEFORE the first
// save overwrites it. The pre-R2 flat `[TransferJob]` array still loads.

import Foundation

/// Where the queue snapshot lives. File-backed in the app; tests inject an
/// in-memory store to count writes.
protocol TransferQueueStore: Sendable {
    /// Current snapshot bytes, or nil when nothing was saved yet.
    func read() -> Data?
    func write(_ data: Data) throws
    /// Preserves the current snapshot (as read) before it is overwritten.
    func backup()
}

/// Atomic JSON file + sibling `.bak` (Application Support in the app).
struct FileTransferQueueStore: TransferQueueStore {
    let url: URL

    var backupURL: URL {
        url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".bak")
    }

    func read() -> Data? {
        try? Data(contentsOf: url)
    }

    func write(_ data: Data) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try data.write(to: url, options: .atomic)
    }

    func backup() {
        guard let data = read() else { return }
        try? data.write(to: backupURL, options: .atomic)
    }
}

/// Versioned snapshot codec (pure).
enum TransferQueueSnapshot {
    /// 1 = pre-R2 flat array (implicit); 2 = `{schemaVersion, jobs}`.
    static let schemaVersion = 2

    struct Decoded: Sendable {
        var jobs: [TransferJob]
        /// True when anything was dropped or not understood (bad JSON, a
        /// record that would not decode, a newer schema): the caller must
        /// back the file up before overwriting it.
        var lossy: Bool
    }

    private struct Envelope: Decodable {
        var schemaVersion: Int?
        var jobs: [Lossy]?
    }

    private struct EncodedEnvelope: Encodable {
        var schemaVersion: Int
        var jobs: [TransferJob]
    }

    /// One array element that may fail to decode without failing the array.
    private struct Lossy: Decodable {
        var job: TransferJob?

        init(from decoder: Decoder) throws {
            job = try? decoder.singleValueContainer().decode(TransferJob.self)
        }
    }

    static func encode(_ jobs: [TransferJob]) throws -> Data {
        try JSONEncoder().encode(EncodedEnvelope(schemaVersion: schemaVersion, jobs: jobs))
    }

    static func decode(_ data: Data) -> Decoded {
        let firstByte = data.first { !($0 == 0x20 || $0 == 0x0A || $0 == 0x0D || $0 == 0x09) }
        let decoder = JSONDecoder()
        if firstByte == UInt8(ascii: "[") {
            // Legacy (schema 1) flat array.
            guard let items = try? decoder.decode([Lossy].self, from: data) else {
                return Decoded(jobs: [], lossy: true)
            }
            let jobs = items.compactMap(\.job)
            return Decoded(jobs: jobs, lossy: jobs.count != items.count)
        }
        guard let env = try? decoder.decode(Envelope.self, from: data), let items = env.jobs else {
            return Decoded(jobs: [], lossy: true)
        }
        let jobs = items.compactMap(\.job)
        let newer = (env.schemaVersion ?? 0) > schemaVersion
        return Decoded(jobs: jobs, lossy: newer || jobs.count != items.count)
    }
}
