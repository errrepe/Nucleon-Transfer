// Nucleon Transfer — EksBlowfish key schedule + bcrypt digest.
// Algorithm adapted from vapor-community/bcrypt Hash.swift (MIT) with native
// Swift types ([UInt8], no external Core/Random/Debugging deps).
// Verifiable against the canonical vector:
//   password "" (empty), salt "$2a$06$DCq7YPn5Rq63x1Lad4cll." -> digest "TV4S6ytwfsfvkgY8jIucDrjc8deX1s."
enum EksBlowfish {
    /// - Parameters:
    ///   - password: raw password bytes (NUL is appended internally per bcrypt spec)
    ///   - salt: 16 decoded salt bytes
    ///   - cost: 4...31 (Proton uses 10)
    /// - Returns: 23-byte raw digest (bcrypt-base64 of this is the last 31 chars)
    static func hash(password: [UInt8], salt: [UInt8], cost: UInt) -> [UInt8] {
        precondition(salt.count == 16, "bcrypt salt must be 16 bytes")
        var p = BcryptTables.p
        var s = BcryptTables.s
        var key = password + [0]
        // The key schedule (p, s) and the NUL-terminated copy are
        // password-derived: zero them on the way out (F8.1-S7, best-effort).
        defer {
            SecureBytes.wipe(&key)
            SecureBytes.wipe(&p)
            SecureBytes.wipe(&s)
        }
        enhance(&p, &s, data: salt, key: key)

        let rounds = 1 << cost
        for _ in 0..<rounds {
            keyExpand(&p, &s, key: key)
            keyExpand(&p, &s, key: salt)
        }

        var cdata = BcryptTables.ctext
        defer { SecureBytes.wipe(&cdata) }
        for _ in 0..<64 {
            for j in 0..<3 {
                encipher(p: p, s: s, lr: &cdata, off: j * 2)
            }
        }

        var out: [UInt8] = []
        out.reserveCapacity(24)
        for word in cdata {
            out.append(UInt8((word >> 24) & 0xFF))
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
            out.append(UInt8(word & 0xFF))
        }
        let digest = Array(out.prefix(23))
        SecureBytes.wipe(&out)
        return digest
    }

    // MARK: - private

    private static func streamToWord(_ data: [UInt8], off: inout Int) -> UInt32 {
        var word: UInt32 = 0
        for _ in 0..<4 {
            word = (word << 8) | UInt32(data[off])
            off = (off + 1) % data.count
        }
        return word
    }

    private static func encipher(p: [UInt32], s: [UInt32], lr: inout [UInt32], off: Int) {
        var l = lr[off]
        var r = lr[off + 1]

        l ^= p[0]
        var i = 0
        while i <= 14 {
            var n = s[Int((l >> 24) & 0xFF)]
            n = n &+ s[Int(0x100 | ((l >> 16) & 0xFF))]
            n ^= s[Int(0x200 | ((l >> 8) & 0xFF))]
            n = n &+ s[Int(0x300 | (l & 0xFF))]
            i += 1
            r ^= n ^ p[i]

            n = s[Int((r >> 24) & 0xFF)]
            n = n &+ s[Int(0x100 | ((r >> 16) & 0xFF))]
            n ^= s[Int(0x200 | ((r >> 8) & 0xFF))]
            n = n &+ s[Int(0x300 | (r & 0xFF))]
            i += 1
            l ^= n ^ p[i]
        }

        lr[off] = r ^ p[17]
        lr[off + 1] = l
    }

    private static func keyExpand(_ p: inout [UInt32], _ s: inout [UInt32], key: [UInt8]) {
        var koff = 0
        for i in 0..<18 {
            p[i] ^= streamToWord(key, off: &koff)
        }
        var lr: [UInt32] = [0, 0]
        var i = 0
        while i < 18 {
            encipher(p: p, s: s, lr: &lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]
            i += 2
        }
        i = 0
        while i < 1024 {
            encipher(p: p, s: s, lr: &lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]
            i += 2
        }
    }

    private static func enhance(_ p: inout [UInt32], _ s: inout [UInt32], data: [UInt8], key: [UInt8]) {
        var koff = 0
        var doff = 0
        var lr: [UInt32] = [0, 0]

        for i in 0..<p.count {
            p[i] ^= streamToWord(key, off: &koff)
        }

        var i = 0
        while i < p.count {
            lr[0] ^= streamToWord(data, off: &doff)
            lr[1] ^= streamToWord(data, off: &doff)
            encipher(p: p, s: s, lr: &lr, off: 0)
            p[i] = lr[0]
            p[i + 1] = lr[1]
            i += 2
        }

        i = 0
        while i < s.count {
            lr[0] ^= streamToWord(data, off: &doff)
            lr[1] ^= streamToWord(data, off: &doff)
            encipher(p: p, s: s, lr: &lr, off: 0)
            s[i] = lr[0]
            s[i + 1] = lr[1]
            i += 2
        }
    }
}
