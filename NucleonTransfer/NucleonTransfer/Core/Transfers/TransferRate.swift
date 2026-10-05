// Nucleon Transfer — smoothed transfer speed + ETA text (F8.4-U6).
// Pure Foundation: progress samples (bytes, timestamp) feed a
// time-weighted EWMA so the popover's "42% · 3.2 MB/s · 1 min left" stays
// steady between bursty block completions. Callers pass the clock
// (`at:` / `now:`) — tests drive it with fixed dates, the app with Date().
// Secrets-free: byte counts and times only.

import Foundation

/// Smoothed byte rate of ONE transfer. Speed (and therefore ETA) stays
/// hidden until enough history exists — the first block of an upload
/// otherwise reads as an absurd burst — and again once samples stop
/// arriving (stalled / paused).
struct TransferRateEstimator: Sendable, Equatable {
    /// EWMA time constant: a sample `dt` seconds after the previous one
    /// weighs `1 - exp(-dt / timeConstant)`. Time-weighting (instead of a
    /// fixed alpha) keeps the average honest when samples arrive unevenly
    /// (coalesced ~100 ms snapshots, 4 MiB download blocks).
    static let timeConstant: TimeInterval = 3
    /// Rate is published only after this many samples…
    static let minSamples = 3
    /// …spanning at least this long.
    static let minElapsed: TimeInterval = 2
    /// No sample for this long → speed unknown (stalled or paused).
    static let staleAfter: TimeInterval = 10
    /// Samples closer than this to the previous one that moved no bytes
    /// are dropped: duplicate observations of the same snapshot.
    static let duplicateWindow: TimeInterval = 0.05

    private(set) var sampleCount = 0
    private(set) var firstTime: Date?
    private(set) var lastTime: Date?
    private(set) var lastBytes: Int64 = 0
    /// Smoothed bytes/second; nil until the second sample.
    private(set) var smoothedRate: Double?

    /// Adds a cumulative-bytes sample. Bytes going backwards (a retry
    /// restarting from zero) or time going backwards resets the history.
    mutating func record(bytes: Int64, at date: Date) {
        guard let lastTime else {
            start(bytes: bytes, at: date)
            return
        }
        let dt = date.timeIntervalSince(lastTime)
        guard bytes >= lastBytes, dt >= 0 else {
            self = TransferRateEstimator()
            start(bytes: bytes, at: date)
            return
        }
        if bytes == lastBytes, dt < Self.duplicateWindow { return }
        guard dt > 0 else {
            // Same instant, more bytes: fold into the next interval.
            lastBytes = bytes
            return
        }
        let instant = Double(bytes - lastBytes) / dt
        let weight = 1 - exp(-dt / Self.timeConstant)
        if let smoothedRate {
            self.smoothedRate = smoothedRate + weight * (instant - smoothedRate)
        } else {
            smoothedRate = instant
        }
        sampleCount += 1
        self.lastTime = date
        lastBytes = bytes
    }

    /// Smoothed bytes/second, or nil while warming up or once stale.
    func bytesPerSecond(now: Date) -> Double? {
        guard sampleCount >= Self.minSamples,
              let firstTime, let lastTime, let smoothedRate,
              lastTime.timeIntervalSince(firstTime) >= Self.minElapsed,
              now.timeIntervalSince(lastTime) <= Self.staleAfter,
              smoothedRate > 0
        else { return nil }
        return smoothedRate
    }

    private mutating func start(bytes: Int64, at date: Date) {
        sampleCount = 1
        firstTime = date
        lastTime = date
        lastBytes = bytes
        smoothedRate = nil
    }
}

/// Estimators keyed by transfer ID (TransferDisplayItem.id) — one book for
/// uploads and downloads alike. Finished transfers are dropped (`remove`,
/// `record(uploads:at:)`) so the book never outgrows the popover.
struct TransferRateBook: Sendable, Equatable {
    private(set) var estimators: [String: TransferRateEstimator] = [:]

    mutating func record(id: String, bytes: Int64, at date: Date) {
        estimators[id, default: TransferRateEstimator()].record(bytes: bytes, at: date)
    }

    func bytesPerSecond(id: String, now: Date) -> Double? {
        estimators[id]?.bytesPerSecond(now: now)
    }

    /// Forgets one transfer (finished, failed, cancelled or removed).
    mutating func remove(id: String) {
        estimators[id] = nil
    }

    /// Feeds every uploading job's byte count and drops the estimators of
    /// upload jobs no longer uploading (paused, finished, removed): a
    /// resumed job warms up afresh, so a pause never drags its average
    /// down. Download estimators are left alone — the activity store
    /// prunes those on its own record transitions.
    mutating func record(uploads: [TransferJob], at date: Date) {
        var live: Set<String> = []
        for job in uploads where job.state == .uploading {
            let id = job.id.uuidString
            live.insert(id)
            record(id: id, bytes: job.bytesDone, at: date)
        }
        for id in uploadIDs.subtracting(live) { estimators[id] = nil }
        uploadIDs = live
    }

    /// Upload ids currently tracked (`record(uploads:at:)`).
    private var uploadIDs: Set<String> = []
}

/// Text fragments for the progress subtitle. Separate from the estimator
/// so the formatting is testable with a fixed locale.
enum TransferRateText {
    /// "3.2 MB/s".
    static func speed(_ bytesPerSecond: Double, locale: Locale = .current) -> String {
        let bytes = Int64(bytesPerSecond.rounded())
            .formatted(ByteCountFormatStyle(style: .file).locale(locale))
        return String(localized: "\(bytes)/s")
    }

    /// Seconds left, or nil when unknowable / unhelpfully far (> 99 h).
    static func secondsRemaining(done: Int64, total: Int64, bytesPerSecond: Double) -> Double? {
        guard total > 0, bytesPerSecond > 0 else { return nil }
        let remaining = Double(max(total - done, 0)) / bytesPerSecond
        guard remaining.isFinite, remaining <= 99 * 3600 else { return nil }
        return remaining
    }

    /// "45 sec left" / "12 min left" / "1 hr, 5 min left". Under a minute
    /// rounds UP to 5 s steps (a countdown that jitters by 1 s reads as
    /// noise); longer spans round up to whole minutes.
    static func eta(seconds: Double, locale: Locale = .current) -> String {
        let text: String
        let stepped = max(5, (seconds / 5).rounded(.up) * 5)
        if stepped < 60 {
            text = Duration.seconds(stepped).formatted(
                .units(allowed: [.seconds], width: .abbreviated).locale(locale)
            )
        } else {
            text = Duration.seconds(seconds).formatted(
                .units(
                    allowed: [.hours, .minutes], width: .abbreviated,
                    maximumUnitCount: 2, fractionalPart: .hide(rounded: .up)
                ).locale(locale)
            )
        }
        return String(localized: "\(text) left")
    }

    /// "42%".
    static func percent(_ fraction: Double) -> String {
        "\(Int((min(max(fraction, 0), 1) * 100).rounded(.down)))%"
    }

    /// "42% · 3.2 MB/s · 1 min left"; speed/ETA appear only with a rate
    /// (and ETA only with a known total). Nil rate → percent only.
    static func progressLine(
        fraction: Double, done: Int64?, total: Int64?,
        bytesPerSecond: Double?, locale: Locale = .current
    ) -> String {
        var parts = [percent(fraction)]
        if let bytesPerSecond {
            parts.append(speed(bytesPerSecond, locale: locale))
            if let done, let total,
               let left = secondsRemaining(done: done, total: total, bytesPerSecond: bytesPerSecond) {
                parts.append(eta(seconds: left, locale: locale))
            }
        }
        return parts.joined(separator: " · ")
    }
}
