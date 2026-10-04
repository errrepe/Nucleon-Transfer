// Nucleon Transfer — third-party client, not affiliated with Proton.
import Foundation

/// Honest client identification required by Proton's third-party rules
/// (ProtonDriveApps/sdk README, "Identify your application"): every request —
/// Drive API and storage host alike — sends `x-pm-appversion` identifying THIS
/// build. The value must accurately represent the application; spoofing or
/// masquerading as another client is forbidden and may get the build blocked.
/// Shape: external-drive-{name}@{semver}-{channel}. Never spoof web-drive/*.
enum AppVersion {
    static let headerValue = "external-drive-nucleon_transfer@0.1.0-alpha"
    static let baseURL = URL(string: "https://mail.proton.me/api")!

    /// Host suffixes a server-supplied storage URL (block BareURL / URL) must
    /// match before any credential is attached to it. The storage host is
    /// only known at runtime (TRANSFERS.md: "host de storage vem do BareURL
    /// em runtime, nunca hardcoded"); the rclone capture used in F5
    /// (/tmp/f5ref, not committed) shows `zrh-storage.proton.me`.
    /// `protonmail.ch` covers Proton's legacy API/storage domain.
    /// Match rule: host == suffix, or host ends with "." + suffix.
    static let storageHostSuffixes = ["proton.me", "protonmail.ch"]
}
