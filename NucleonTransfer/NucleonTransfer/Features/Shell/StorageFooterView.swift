// Nucleon Transfer — sidebar footer: storage quota + account/sign-out (S2.1).
// Quota bar tint escalates with occupancy (accent → orange → red) and hides
// entirely when the account has no quota. The account menu is always rendered
// so Sign Out stays reachable even if /users failed.
// Polish pass: the quota bar fills from empty when the sidebar first
// appears and eases to new values (static under Reduce Motion); the
// "used" figure rolls. Pass 3: the account is refreshed ~2 s after the
// app changes the drive (uploads, new folders, trash — the
// remoteChangedToken bumps), so the gauge follows them.
import SwiftUI

struct StorageFooterView: View {
    @Environment(AppSession.self) private var session
    @State private var showSignOutConfirm = false
    @State private var hasActiveTransfers = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// False until the footer is on screen — the gauge fills from zero.
    @State private var gaugeFilled = false

    /// used/max byte counts for the quota bar; nil when the account
    /// reports no quota (bar hidden, text still renders).
    private var quota: (used: Int64, max: Int64)? {
        guard let account = session.account,
              let max = account.maxBytes, max > 0 else { return nil }
        return (account.usedBytes, max)
    }

    /// "1.2 GB of 5 GB used"-style text shared by the caption and the
    /// gauge's accessibility value.
    private var storageText: String? {
        session.account.map { DriveFormatting.storage(used: $0.usedBytes, max: $0.maxBytes) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            #if DEBUG
            if session.isDemo {
                Text("Demo Mode")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(.orange.opacity(0.15), in: Capsule())
                    .help("Offline sample data — nothing is sent or stored.")
            }
            #endif
            if let quota {
                // M2: linearCapacity paints a filled track — far higher
                // contrast than ProgressView's thin line in dark mode
                // (the QA complaint). The occupancy tint is unchanged.
                Gauge(value: gaugeFilled ? Double(quota.used) : 0, in: 0...Double(quota.max)) {
                    EmptyView()
                }
                .gaugeStyle(.linearCapacity)
                .tint(quotaTint(for: Double(quota.used) / Double(quota.max)))
                .animation(reduceMotion ? nil : .smooth(duration: 0.8), value: gaugeFilled ? quota.used : 0)
                .onAppear { gaugeFilled = true }
                // F8.4-U8: the label is visually empty — name it for
                // VoiceOver and read the same "used of total" text.
                .accessibilityLabel("Storage")
                .accessibilityValue(storageText ?? "")
            }
            if let storageText {
                Text(storageText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .contentTransition(Motion.numeric(
                        Double(session.account?.usedBytes ?? 0), reduceMotion: reduceMotion
                    ))
                    .animation(Motion.snappy, value: session.account?.usedBytes)
            }
            accountRow
        }
        .padding(12)
        // Debounced refresh after the app changed the drive: each bump
        // cancels the pending one, so a 300-file upload costs one /users
        // call at the end. Token 0 is the session start (sign-in already
        // fetched the account).
        .task(id: session.activity.remoteChangedToken) {
            guard session.activity.remoteChangedToken > 0 else { return }
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            await session.refreshAccount()
        }
        .confirmationDialog(
            hasActiveTransfers
                ? "Sign out? Active transfers will be paused."
                : "Sign out of \(session.account?.email ?? String(localized: "this account"))?",
            isPresented: $showSignOutConfirm,
            titleVisibility: .visible
        ) {
            Button("Sign Out", role: .destructive) {
                Task { await session.signOut() }
            }
            Button("Cancel", role: .cancel) {}
        }
        // S4.2: the App-menu "Sign Out…" command routes here (through
        // AppSession.signOutRequested — it works from the Settings window
        // too) so it lands on this same confirmationDialog, with the
        // active-transfers warning, instead of a second, divergent flow.
        // `initial`: the request may predate this view (window reopened).
        .onChange(of: session.signOutRequested, initial: true) { _, requested in
            guard requested else { return }
            session.signOutRequested = false
            beginSignOut()
        }
    }

    private var accountRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "person.crop.circle")
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 0) {
                Text(session.account?.displayName ?? String(localized: "Account"))
                    .font(.callout)
                    .lineLimit(1)
                if let email = session.account?.email, !email.isEmpty {
                    Text(email)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            Menu {
                Button("Sign Out…") { beginSignOut() }
            } label: {
                Label("Account Options", systemImage: "ellipsis.circle")
                    .labelStyle(.iconOnly)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .fixedSize()
            .help("Account Options")
        }
    }

    /// accent under 80%, orange under 95%, red at/above — matches spec 6.1.
    private func quotaTint(for fraction: Double) -> Color {
        if fraction < 0.8 { return .accentColor }
        if fraction < 0.95 { return .orange }
        return .red
    }

    /// Reads the queue snapshot right before confirming — the TransferQueue
    /// actor has no synchronous job-state read, so the check runs on tap
    /// (no polling). Downloads in flight count as active transfers too.
    private func beginSignOut() {
        Task {
            let jobs = await session.queue.snapshot()
            hasActiveTransfers =
                jobs.contains { $0.state == .queued || $0.state == .uploading }
                || session.activity.downloads.contains { $0.state == .downloading }
            showSignOutConfirm = true
        }
    }
}

#if DEBUG
#Preview("Light") {
    StorageFooterView()
        .environment(PreviewFixtures.session())
        .frame(width: 220)
        .preferredColorScheme(.light)
}

#Preview("Dark") {
    StorageFooterView()
        .environment(PreviewFixtures.session())
        .frame(width: 220)
        .preferredColorScheme(.dark)
}

#Preview("Demo Mode") {
    StorageFooterView()
        .environment(AppSession.demo())
        .frame(width: 220)
        .preferredColorScheme(.light)
}
#endif
