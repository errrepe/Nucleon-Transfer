// Nucleon Transfer — ASCII armor decode/encode (RFC 4880 §6). The CRC24
// line is optional; when present it must match (F8.3-P2).
import Foundation

enum ArmorError: Error, Sendable {
    case noBeginLine
    case invalidBase64
    /// The armor's CRC24 line does not match the decoded bytes.
    case crcMismatch
}

enum Armor {
    /// F8.3-P2: one pass over the UTF-8 bytes (no per-line String
    /// allocations); body bytes are copied into a single buffer that
    /// Foundation's base64 decoder consumes. Same acceptance as before:
    /// lines before BEGIN and armor headers (`Key: value`) are skipped,
    /// decoding stops at END. A `=`-prefixed CRC24 line, when present, is
    /// now checked (table-driven CRC — RFC 4880 §6.1); it stays optional
    /// (RFC 9580 §6.1 makes it so; gopenpgp v3 omits it).
    static func decode(_ text: String) throws -> Data {
        var text = text
        let scanned: (sawBegin: Bool, body: Data, crc: Data) = text.withUTF8 { bytes in
            var b64 = Data()
            b64.reserveCapacity(bytes.count)
            var crc = Data()
            var inBody = false
            var sawBegin = false
            var i = 0
            let n = bytes.count
            let dash = UInt8(ascii: "-"), colon = UInt8(ascii: ":"), equals = UInt8(ascii: "=")
            let cr = UInt8(ascii: "\r"), lf = UInt8(ascii: "\n")
            func hasPrefix(_ p: StaticString, at s: Int, end: Int) -> Bool {
                let len = p.utf8CodeUnitCount
                guard end - s >= len else { return false }
                return p.withUTF8Buffer { pb in
                    for k in 0..<len where bytes[s + k] != pb[k] { return false }
                    return true
                }
            }
            while i < n {
                var end = i
                while end < n, bytes[end] != lf { end += 1 }
                var lineEnd = end
                if lineEnd > i, bytes[lineEnd - 1] == cr { lineEnd -= 1 }
                let s = i
                i = end + 1
                if lineEnd > s, bytes[s] == dash {
                    if hasPrefix("-----BEGIN", at: s, end: lineEnd) { inBody = true; sawBegin = true; continue }
                    if hasPrefix("-----END", at: s, end: lineEnd) { break }
                }
                guard inBody, lineEnd > s else { continue }
                let line = UnsafeBufferPointer(rebasing: bytes[s..<lineEnd])
                if bytes[s] == equals { // CRC24 line
                    crc = Data(line.dropFirst())
                    continue
                }
                if line.contains(colon) { continue } // armor headers (Version/Comment/...)
                b64.append(line)
            }
            return (sawBegin, b64, crc)
        }
        guard scanned.sawBegin else { throw ArmorError.noBeginLine }
        guard let data = Data(base64Encoded: scanned.body, options: .ignoreUnknownCharacters) else {
            throw ArmorError.invalidBase64
        }
        if !scanned.crc.isEmpty {
            guard let expected = Data(base64Encoded: scanned.crc, options: .ignoreUnknownCharacters),
                  expected.count == 3, expected == crc24Bytes(data)
            else { throw ArmorError.crcMismatch }
        }
        return data
    }

    /// ASCII-armors packet bytes (RFC 4880 §6): BEGIN/END lines, 64-column
    /// base64, CRC24 trailer. Inverse of decode.
    static func encode(_ data: Data, header: String = "MESSAGE") -> String {
        let b64 = data.base64EncodedString()
        var lines = ["-----BEGIN PGP \(header)-----", ""]
        var i = b64.startIndex
        while i < b64.endIndex {
            let j = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[i..<j]))
            i = j
        }
        lines.append("=" + crc24(data))
        lines.append("-----END PGP \(header)-----")
        return lines.joined(separator: "\n") + "\n"
    }

    /// CRC24 (RFC 4880 §6.1): poly 0x1864CFB, init 0xB704CE — base64 of
    /// the 3 big-endian bytes.
    private static func crc24(_ data: Data) -> String {
        crc24Bytes(data).base64EncodedString()
    }

    /// Byte-at-a-time table CRC24 (same polynomial/init as the bitwise
    /// RFC reference; ~8× fewer steps for multi-MiB armor).
    static func crc24Bytes(_ data: Data) -> Data {
        var crc: UInt32 = 0xB704CE
        data.withUnsafeBytes { raw in
            for byte in raw {
                crc = (crc << 8) ^ crc24Table[Int(((crc >> 16) ^ UInt32(byte)) & 0xFF)]
            }
        }
        crc &= 0xFFFFFF
        return Data([UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)])
    }

    private static let crc24Table: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i) << 16
        for _ in 0..<8 {
            c <<= 1
            if c & 0x1000000 != 0 { c ^= 0x1864CFB }
        }
        return c & 0xFFFFFF
    }
}
