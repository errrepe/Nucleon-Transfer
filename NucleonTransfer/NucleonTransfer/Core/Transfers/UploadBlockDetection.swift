// Nucleon Transfer — "uploads blocked" detection (F8.4-U1).
// Proton's block-upload endpoint answers code 2000 while this app's
// appversion is not on its allowlist (live-proven F6). Instead of letting
// every queued file fail with its own message, the first 2000 failure
// seen in THIS run flips one app-level flag (UploadCoordinator) that
// disables the upload entry points and shows a single banner. Failures
// restored from disk don't count — the flag is never persisted, so a
// relaunch re-probes and picks up a server-side change.
import Foundation

enum UploadBlockDetection {
    /// Proton API code for "app version not allowlisted for block upload".
    static let notAllowlistedCode = 2000

    /// True for a job that failed because the server refused uploads from
    /// this app (typed code, never message text).
    static func isNotAllowlisted(_ job: TransferJob) -> Bool {
        job.state == .failed && job.errorCode == notAllowlistedCode
    }

    /// Scans a queue snapshot for failures that appeared since `knownFailed`
    /// (the failed IDs of the previous snapshot). Returns the snapshot's
    /// failed IDs — the next call's `knownFailed` — and whether one of the
    /// NEW failures is an allowlist rejection. A job retried and failing
    /// again counts as new (it left `.failed` in between).
    static func scan(
        _ snapshot: [TransferJob],
        knownFailed: Set<UUID>
    ) -> (failed: Set<UUID>, blocked: Bool) {
        var failed: Set<UUID> = []
        var blocked = false
        for job in snapshot where job.state == .failed {
            failed.insert(job.id)
            if !knownFailed.contains(job.id), isNotAllowlisted(job) {
                blocked = true
            }
        }
        return (failed, blocked)
    }
}
