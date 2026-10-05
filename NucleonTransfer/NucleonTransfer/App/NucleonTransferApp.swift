// Nucleon Transfer — app entry point (F7 S4.2): a single main window
// (`Window`, not WindowGroup — there is exactly one drive browser), the
// menu commands (AppCommands; DebugCommands in DEBUG builds), and the
// Settings scene. The launch `.task`
// applies the persisted "simultaneous uploads" cap to the TransferQueue;
// the Settings stepper writes the same key and applies on change.
// Quit (F8.2-R2): the queue coalesces its snapshot writes, so termination
// is deferred until `TransferQueue.flush()` has written pending changes.
import AppKit
import SwiftUI

@main
struct NucleonTransferApp: App {
    #if DEBUG
    // `-NTDemoMode YES` lands in the argument domain of UserDefaults and
    // boots the offline demo session (R1).
    @State private var session = UserDefaults.standard.bool(forKey: "NTDemoMode") ? AppSession.demo() : AppSession()
    #else
    @State private var session = AppSession()
    #endif
    @NSApplicationDelegateAdaptor(AppQuitFlush.self) private var quitFlush

    var body: some Scene {
        Window("Nucleon Transfer", id: "main") {
            RootView()
                .environment(session)
                .task {
                    quitFlush.flush = { [queue = session.queue] in await queue.flush() }
                    await session.queue.setMaxConcurrent(
                        AppSettings.maxConcurrentUploads(.standard)
                    )
                }
        }
        .defaultSize(width: 1100, height: 700)
        .windowToolbarStyle(.unified)
        .commands {
            AppCommands(session: session)
            // F8.5-V3: empty in release builds (#if DEBUG inside).
            DebugCommands()
        }

        Settings {
            SettingsView()
                .environment(session)
        }
    }
}

/// Defers app termination until the upload queue's coalesced snapshot is
/// on disk. Synchronous delegate method on purpose (no async @objc thunk —
/// swift-frontend 6.4 crashes on those); the flush runs in a MainActor
/// Task and replies when done.
@MainActor
final class AppQuitFlush: NSObject, NSApplicationDelegate {
    var flush: (@Sendable () async -> Void)?
    private var flushing = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let flush, !flushing else { return .terminateNow }
        flushing = true
        Task { @MainActor in
            await flush()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
