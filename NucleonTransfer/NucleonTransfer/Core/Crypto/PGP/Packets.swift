// Nucleon Transfer — OpenPGP packet framing (RFC 4880 §4).
// Supports new-format definite lengths, partial body lengths (concatenated,
// as used by streamed encrypted-data packets) and old-format 1/2/4-octet
// lengths + indeterminate (rest of data). `parseSlices` hands out
// definite-length bodies as slices of the input (no copy, F8.3-P1).
import Foundation

enum PacketError: Error, Sendable {
    case truncated
    case indeterminateInSequence
}

struct PGPPacket: Sendable {
    /// Packet tag (0-63). Key packets: 5 secret, 6 public, 7 secret-subkey,
    /// 14 public-subkey; 2 signature; 1 PKESK; 3 SKESK; 8 compressed; 9 SEIPDv1;
    /// 11 literal; 13 user ID; 17 attribute; 18 SEIPDv2; 19 padding.
    var tag: Int
    var body: Data
}

enum PGPPackets {
    /// Parses packets with ZERO-BASED bodies (each body is its own Data):
    /// safe for consumers that index bodies with absolute offsets.
    static func parse(_ data: Data) throws -> [PGPPacket] {
        try parseSlices(data).map { p in
            p.body.startIndex == 0 ? p : PGPPacket(tag: p.tag, body: Data(p.body))
        }
    }

    /// Same framing as `parse`, but definite-length bodies are slices of
    /// `data` (shared storage, no copy; `startIndex` is generally non-zero).
    /// Partial-length bodies are concatenated into a fresh buffer. Only for
    /// consumers that index bodies relative to `startIndex` (F8.3-P1: the
    /// multi-MiB SEIPD/literal decrypt path).
    static func parseSlices(_ data: Data) throws -> [PGPPacket] {
        var out: [PGPPacket] = []
        var i = data.startIndex
        let end = data.endIndex
        while i < end {
            let b0 = data[i]
            guard b0 & 0x80 != 0 else { throw PacketError.truncated }
            if b0 & 0x40 != 0 {
                // New format.
                let tag = Int(b0 & 0x3F)
                i = data.index(after: i)
                // Single definite chunk → slice; partial chunks → appended.
                var body: Data? = nil
                func add(_ chunk: Data) {
                    if body == nil { body = chunk } else { body!.append(chunk) }
                }
                while true {
                    guard i < end else { throw PacketError.truncated }
                    let l0 = Int(data[i])
                    if l0 < 192 {
                        let len = l0
                        i = data.index(i, offsetBy: 1)
                        guard let sliceEnd = data.index(i, offsetBy: len, limitedBy: end),
                              sliceEnd <= end else { throw PacketError.truncated }
                        add(data[i..<sliceEnd])
                        i = sliceEnd
                        break // definite: packet complete
                    } else if l0 < 224 {
                        guard data.index(i, offsetBy: 1) < end else { throw PacketError.truncated }
                        let len = ((l0 - 192) << 8) + Int(data[data.index(i, offsetBy: 1)]) + 192
                        i = data.index(i, offsetBy: 2)
                        guard let sliceEnd = data.index(i, offsetBy: len, limitedBy: end) else {
                            throw PacketError.truncated
                        }
                        add(data[i..<sliceEnd])
                        i = sliceEnd
                        break
                    } else if l0 < 255 {
                        // Partial body length: 1 << (l0 & 0x1F) bytes, more chunks follow.
                        let len = 1 << (l0 & 0x1F)
                        i = data.index(i, offsetBy: 1)
                        guard let sliceEnd = data.index(i, offsetBy: len, limitedBy: end) else {
                            throw PacketError.truncated
                        }
                        add(data[i..<sliceEnd])
                        i = sliceEnd
                        continue
                    } else {
                        guard let l1 = data.index(i, offsetBy: 4, limitedBy: end) else {
                            throw PacketError.truncated
                        }
                        let len = (Int(data[data.index(i, offsetBy: 1)]) << 24)
                            | (Int(data[data.index(i, offsetBy: 2)]) << 16)
                            | (Int(data[data.index(i, offsetBy: 3)]) << 8)
                            | Int(data[l1])
                        i = data.index(i, offsetBy: 5)
                        guard let sliceEnd = data.index(i, offsetBy: len, limitedBy: end) else {
                            throw PacketError.truncated
                        }
                        add(data[i..<sliceEnd])
                        i = sliceEnd
                        break
                    }
                }
                out.append(PGPPacket(tag: tag, body: body ?? Data()))
            } else {
                // Old format.
                let tag = Int((b0 >> 2) & 0x0F)
                let lenType = b0 & 0x03
                i = data.index(after: i)
                let len: Int?
                switch lenType {
                case 0:
                    guard i < end else { throw PacketError.truncated }
                    len = Int(data[i]); i = data.index(after: i)
                case 1:
                    guard data.index(i, offsetBy: 1) < end else { throw PacketError.truncated }
                    len = (Int(data[i]) << 8) | Int(data[data.index(i, offsetBy: 1)])
                    i = data.index(i, offsetBy: 2)
                case 2:
                    guard let e = data.index(i, offsetBy: 3, limitedBy: end) else {
                        throw PacketError.truncated
                    }
                    len = (Int(data[i]) << 24) | (Int(data[data.index(i, offsetBy: 1)]) << 16)
                        | (Int(data[data.index(i, offsetBy: 2)]) << 8) | Int(data[e])
                    i = data.index(i, offsetBy: 4)
                default:
                    len = nil // indeterminate: rest of data
                }
                if let len {
                    guard let sliceEnd = data.index(i, offsetBy: len, limitedBy: end) else {
                        throw PacketError.truncated
                    }
                    out.append(PGPPacket(tag: tag, body: data[i..<sliceEnd]))
                    i = sliceEnd
                } else {
                    out.append(PGPPacket(tag: tag, body: data[i..<end]))
                    i = end
                }
            }
        }
        return out
    }
}
