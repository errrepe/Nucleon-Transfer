// Nucleon Transfer — F6 hardening suite (Swift Testing).
// Offline only: error mapping, Bool-tolerant share flags, download records.
// No network, no secrets.
import Foundation
import Testing

@testable import NucleonTransfer

struct UserFacingErrorTests {
    @Test func rateLimitedGuidesWait() {
        let msg = UserFacingError.message(for: ProtonAPIError.rateLimited)
        #expect(msg.contains("2028"))
        #expect(msg.lowercased().contains("wait"))
        #expect(msg.lowercased().contains("10 minute"))
    }

    @Test func api2028MapsToWait() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(code: 2028, message: "too many"))
        #expect(msg.lowercased().contains("wait"))
    }

    @Test func humanVerificationPauses() {
        let msg = UserFacingError.message(for: ProtonAPIError.humanVerificationRequired)
        #expect(msg.hasSuffix("(Error 9001)"))
        #expect(msg.lowercased().contains("human verification"))
    }

    @Test func unauthorizedAsksSignIn() {
        let msg = UserFacingError.message(for: ProtonAPIError.unauthorized)
        #expect(msg.lowercased().contains("sign in"))
    }

    @Test func needs2FAActionable() {
        let msg = UserFacingError.message(for: ProtonAPIError.needs2FA)
        #expect(msg.lowercased().contains("two-factor"))
    }

    @Test func transient429BacksOff() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(code: 429, message: "slow"))
        #expect(msg.hasSuffix("(Error 429)"))
        #expect(msg.lowercased().contains("retry"))
    }

    @Test func server5xxRetries() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(code: 503, message: "down"))
        #expect(msg.hasSuffix("(Error 503)"))
        #expect(msg.lowercased().contains("try again"))
    }

    @Test func photoShare2511GuidesDrive() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(code: 2511, message: "photo"))
        #expect(msg.hasSuffix("(Error 2511)"))
        #expect(msg.contains("My Files"))
    }

    @Test func networkOfflineActionable() {
        let msg = UserFacingError.message(for: ProtonAPIError.transport(URLError(.notConnectedToInternet)))
        #expect(msg.lowercased().contains("connection") || msg.lowercased().contains("network"))
    }

    @Test func hashMismatchActionable() {
        let msg = UserFacingError.message(for: FileDownloadError.hashMismatch(index: 2))
        #expect(msg.lowercased().contains("integrity"))
        #expect(msg.lowercased().contains("try again"))
    }

    @Test func transferFailureHVMaps() {
        let msg = UserFacingError.message(for: TransferFailure.needsHumanVerification)
        #expect(msg.contains("9001"))
    }

    @Test func stringHeuristicsUpgrade() {
        #expect(UserFacingError.message(forMessage: "api 2028: too many").lowercased().contains("wait"))
        #expect(UserFacingError.message(forMessage: "rate limited").lowercased().contains("wait"))
        #expect(UserFacingError.message(forMessage: "HV 9001 required").contains("9001"))
        #expect(UserFacingError.message(forMessage: "api 429: slow").contains("429"))
        #expect(UserFacingError.message(forMessage: "api 400: bad").hasSuffix("(Error 400)"))
    }

    @Test func api2000UploadAllowlistHonest() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(
            code: 2000, message: "You are using an outdated version of the app. Please update to upload this file."))
        #expect(msg == "Upload not available yet (Error 2000).")
    }

    @Test func api2000StringHeuristic() {
        let msg = UserFacingError.message(forMessage: "api 2000: You are using an outdated version of the app.")
        #expect(msg == "Upload not available yet (Error 2000).")
    }

    @Test func api2501ExplainsWithoutEchoingJargon() {
        let msg = UserFacingError.message(for: ProtonAPIError.api(code: 2501, message: "Draft file not found"))
        #expect(msg.hasSuffix("(Error 2501)"))
        #expect(msg.contains("may already be gone"))
    }
}

struct CheckAvailableHashesTests {
    @Test func emptyPendingDecodes() throws {
        // The only shape the rclone reference captured (resp-2/3.json).
        let res = try JSONDecoder().decode(CheckAvailableHashesResponse.self, from: """
            {"AvailableHashes":["49c3b9972757e1fb3f37bd96f02a20066c32e702a6b8b1f9321a2c40190ac933"],"PendingHashes":[],"Code":1000}
            """.data(using: .utf8)!)
        #expect(res.availableHashes.count == 1)
        #expect(res.pendingHashes.isEmpty)
    }

    @Test func objectPendingDecodes() throws {
        // Live shape (F6 battery): a stale state=0 draft turns the probed
        // hash pending and the server returns objects, not strings.
        let res = try JSONDecoder().decode(CheckAvailableHashesResponse.self, from: """
            {"AvailableHashes":[],"PendingHashes":[{"Hash":"dc0daee45550da6749443a77a98f281fabf0cef27a6deb896545ed3404e4503b","RevisionID":"QdrYkx5NN4LEYE-Tallcww","LinkID":"3UaNbhkZFWhbrHmkKDQgIQ","ClientUID":null}],"Code":1000}
            """.data(using: .utf8)!)
        #expect(res.availableHashes.isEmpty)
        #expect(res.pendingHashes.count == 1)
        #expect(res.pendingHashes[0].hash?.hasPrefix("dc0daee4") == true)
        #expect(res.pendingHashes[0].revisionID == "QdrYkx5NN4LEYE-Tallcww")
        #expect(res.pendingHashes[0].linkID == "3UaNbhkZFWhbrHmkKDQgIQ")
        #expect(res.pendingHashes[0].clientUID == nil)
    }
}

struct ShareMetadataBoolTests {
    func json(locked: String, softDeleted: String) -> Data {
        """
        {"ShareID":"S","LinkID":"L","VolumeID":"V","Type":2,"State":1,
         "CreationTime":1,"ModifyTime":2,"Locked":\(locked),"VolumeSoftDeleted":\(softDeleted)}
        """.data(using: .utf8)!
    }

    @Test func boolFormsDecode() throws {
        let t = try JSONDecoder().decode(ShareMetadata.self, from: json(locked: "true", softDeleted: "false"))
        #expect(t.locked == true)
        #expect(t.volumeSoftDeleted == false)
    }

    @Test func intFormsDecode() throws {
        let one = try JSONDecoder().decode(ShareMetadata.self, from: json(locked: "1", softDeleted: "0"))
        #expect(one.locked == true)
        #expect(one.volumeSoftDeleted == false)
        let zero = try JSONDecoder().decode(ShareMetadata.self, from: json(locked: "0", softDeleted: "1"))
        #expect(zero.locked == false)
        #expect(zero.volumeSoftDeleted == true)
    }

    @Test func missingAndNullDecodeNil() throws {
        let missing = try JSONDecoder().decode(
            ShareMetadata.self,
            from: """
            {"ShareID":"S","LinkID":"L","VolumeID":"V","Type":2,"State":1,"CreationTime":1,"ModifyTime":2}
            """.data(using: .utf8)!
        )
        #expect(missing.locked == nil)
        #expect(missing.volumeSoftDeleted == nil)
        let nul = try JSONDecoder().decode(
            ShareMetadata.self,
            from: json(locked: "null", softDeleted: "null")
        )
        #expect(nul.locked == nil)
        #expect(nul.volumeSoftDeleted == nil)
    }

    @Test func stringFormsDecode() throws {
        let s = try JSONDecoder().decode(ShareMetadata.self, from: json(locked: "\"1\"", softDeleted: "\"false\""))
        #expect(s.locked == true)
        #expect(s.volumeSoftDeleted == false)
    }

    @Test func encodeRoundTripAsBool() throws {
        let m = ShareMetadata(
            shareID: "S", linkID: "L", volumeID: "V", type: 2, state: 1,
            creationTime: 1, modifyTime: 2, locked: true, volumeSoftDeleted: false
        )
        let data = try JSONEncoder().encode(m)
        let back = try JSONDecoder().decode(ShareMetadata.self, from: data)
        #expect(back.locked == true)
        #expect(back.volumeSoftDeleted == false)
        let text = String(data: data, encoding: .utf8)!
        #expect(text.contains("\"Locked\":true"))
    }
}

struct DownloadRecordTests {
    @Test func labelsAndSummary() {
        var rec = DownloadRecord(name: "a.txt", kind: .file)
        #expect(rec.state == .downloading)
        #expect(rec.stateLabel == "Downloading")
        rec.state = .done
        rec.destinationName = "Dest"
        #expect(rec.summary.contains("Downloaded"))
        var folder = DownloadRecord(name: "pics", kind: .folder, state: .done, fileCount: 3, destinationName: "Out")
        #expect(folder.summary.contains("3 file"))
        folder.state = .failed
        folder.errorMessage = "boom"
        #expect(folder.summary == "boom")
    }

    @Test func codableRoundTrip() throws {
        let rec = DownloadRecord(name: "f.bin", kind: .file, state: .done, fileCount: 1, destinationName: "D")
        let back = try JSONDecoder().decode(DownloadRecord.self, from: try JSONEncoder().encode(rec))
        #expect(back == rec)
    }

    @Test func progressDefaultsToNil() {
        // S2.3: live 0…1 fraction while downloading; unknown until the
        // first block lands (folders report file counts instead).
        let rec = DownloadRecord(name: "a.txt", kind: .file)
        #expect(rec.progress == nil)
    }

    @Test func progressCodableRoundTrip() throws {
        let rec = DownloadRecord(name: "big.iso", kind: .file, progress: 0.42)
        let back = try JSONDecoder().decode(DownloadRecord.self, from: try JSONEncoder().encode(rec))
        #expect(back == rec)
        #expect(back.progress == 0.42)
    }

    @Test func progressDecodesFromLegacyJSON() throws {
        // Records written before S2.3 have no `progress` key — decoding
        // must not fail (optional field → decodeIfPresent).
        let json = """
            {"id":"\(UUID().uuidString)","name":"old.bin","kind":"file",
             "state":"done","fileCount":1,"startedAt":0,"updatedAt":0}
            """.data(using: .utf8)!
        let back = try JSONDecoder().decode(DownloadRecord.self, from: json)
        #expect(back.progress == nil)
        #expect(back.state == .done)
    }

    @Test func holdsNoSecrets() throws {
        let rec = DownloadRecord(name: "a.txt", kind: .file, state: .downloading)
        let json = String(data: try JSONEncoder().encode([rec]), encoding: .utf8)!.lowercased()
        for banned in ["seed", "token", "passphrase", "secret", "accesstoken", "refresh"] {
            #expect(!json.contains(banned), "record leaks \(banned)")
        }
    }
}
