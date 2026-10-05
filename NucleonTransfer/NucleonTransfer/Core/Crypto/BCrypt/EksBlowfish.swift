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
        var cdata = BcryptTables.ctext
        // The key schedule (p, s), the NUL-terminated copy and the cipher
        // state are password-derived: zero them on the way out (F8.1-S7,
        // best-effort). The arrays are mutated in place through the buffer
        // pointers below, so these wipes still cover the live storage.
        defer {
            SecureBytes.wipe(&key)
            SecureBytes.wipe(&p)
            SecureBytes.wipe(&s)
            SecureBytes.wipe(&cdata)
        }
        // F8.3-P5: the whole schedule runs on unsafe buffers (no per-call
        // array copies or retain/release, no bounds checks in release).
        p.withUnsafeMutableBufferPointer { pBuf in
            s.withUnsafeMutableBufferPointer { sBuf in
                key.withUnsafeBufferPointer { keyBuf in
                    salt.withUnsafeBufferPointer { saltBuf in
                        cdata.withUnsafeMutableBufferPointer { cBuf in
                            let st = Schedule(p: pBuf, s: sBuf)
                            st.enhance(data: saltBuf, key: keyBuf)
                            let rounds = 1 << cost
                            for _ in 0..<rounds {
                                st.expand(key: keyBuf)
                                st.expand(key: saltBuf)
                            }
                            for _ in 0..<64 {
                                for j in 0..<3 {
                                    var l = cBuf[2 * j], r = cBuf[2 * j + 1]
                                    st.encipher(&l, &r)
                                    cBuf[2 * j] = l
                                    cBuf[2 * j + 1] = r
                                }
                            }
                        }
                    }
                }
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

    /// Blowfish state viewed through the caller's buffers (valid only inside
    /// the `withUnsafe...` closures in `hash`).
    private struct Schedule {
        let p: UnsafeMutableBufferPointer<UInt32> // 18 subkeys
        let s: UnsafeMutableBufferPointer<UInt32> // 4 S-boxes x 256

        /// Next big-endian word from `data`, wrapping cyclically.
        @inline(__always)
        func streamToWord(_ data: UnsafeBufferPointer<UInt8>, off: inout Int) -> UInt32 {
            var word: UInt32 = 0
            for _ in 0..<4 {
                word = (word << 8) | UInt32(data[off])
                off += 1
                if off == data.count { off = 0 }
            }
            return word
        }

        /// Blowfish round function F.
        @inline(__always)
        func f(_ x: UInt32) -> UInt32 {
            var n = s[Int(x >> 24)]
            n = n &+ s[0x100 | Int((x >> 16) & 0xFF)]
            n ^= s[0x200 | Int((x >> 8) & 0xFF)]
            return n &+ s[0x300 | Int(x & 0xFF)]
        }

        /// 16-round Blowfish encryption of (l, r) in place.
        @inline(__always)
        func encipher(_ l: inout UInt32, _ r: inout UInt32) {
            var xl = l ^ p[0]
            var xr = r
            var i = 1
            while i <= 15 {
                xr ^= f(xl) ^ p[i]
                xl ^= f(xr) ^ p[i + 1]
                i += 2
            }
            l = xr ^ p[17]
            r = xl
        }

        /// Fills p then s with successive encryptions of (l, r).
        @inline(__always)
        private func refill(_ l: inout UInt32, _ r: inout UInt32,
                            mixing data: UnsafeBufferPointer<UInt8>?, off: inout Int) {
            var i = 0
            while i < 18 {
                if let data {
                    l ^= streamToWord(data, off: &off)
                    r ^= streamToWord(data, off: &off)
                }
                encipher(&l, &r)
                p[i] = l
                p[i + 1] = r
                i += 2
            }
            i = 0
            while i < 1024 {
                if let data {
                    l ^= streamToWord(data, off: &off)
                    r ^= streamToWord(data, off: &off)
                }
                encipher(&l, &r)
                s[i] = l
                s[i + 1] = r
                i += 2
            }
        }

        /// ExpandKey(state, 0, key) — the cost loop's step.
        func expand(key: UnsafeBufferPointer<UInt8>) {
            var koff = 0
            for i in 0..<18 { p[i] ^= streamToWord(key, off: &koff) }
            var l: UInt32 = 0, r: UInt32 = 0, unused = 0
            refill(&l, &r, mixing: nil, off: &unused)
        }

        /// ExpandKey(state, salt, key) — the initial salted expansion.
        func enhance(data: UnsafeBufferPointer<UInt8>, key: UnsafeBufferPointer<UInt8>) {
            var koff = 0
            for i in 0..<18 { p[i] ^= streamToWord(key, off: &koff) }
            var l: UInt32 = 0, r: UInt32 = 0, doff = 0
            refill(&l, &r, mixing: data, off: &doff)
        }
    }
}
