// Nucleon Transfer — shared motion vocabulary (UI polish pass).
// One place for the app's animation curves and transitions so every
// screen moves the same way: short, system-like springs for state swaps,
// a top-edge slide for banners, a soft fade + scale for full-screen
// phases. Everything collapses to a plain crossfade (or nothing) under
// System Settings ▸ Accessibility ▸ Display ▸ Reduce motion — callers
// read `accessibilityReduceMotion` and pass it in.
import SwiftUI

enum Motion {
    /// State swaps inside one screen (overlay states, inline errors,
    /// button content). Quick enough to never delay input.
    static let snappy = Animation.snappy(duration: 0.25)
    /// Larger layout changes (banners, phase switches).
    static let smooth = Animation.smooth(duration: 0.35)

    /// `animation`, or a short crossfade when Reduce Motion is on —
    /// opacity changes are still allowed; movement and scale are not.
    static func adaptive(_ animation: Animation, reduceMotion: Bool) -> Animation {
        reduceMotion ? .easeInOut(duration: 0.15) : animation
    }

    /// Banner strips: slide down from under the toolbar and fade.
    static func banner(reduceMotion: Bool) -> AnyTransition {
        reduceMotion ? .opacity : .move(edge: .top).combined(with: .opacity)
    }

    /// Full-screen phase swaps (auth ▸ unlocking ▸ browser): fade with a
    /// slight scale so the new screen settles into place.
    static func phase(reduceMotion: Bool) -> AnyTransition {
        reduceMotion ? .opacity : .opacity.combined(with: .scale(scale: 0.98))
    }

    /// Inline messages (errors, hints) that appear under a field.
    static func inline(reduceMotion: Bool) -> AnyTransition {
        reduceMotion ? .opacity : .opacity.combined(with: .offset(y: -4))
    }
}

/// Horizontal shake — macOS's "that didn't work" for a rejected password
/// or code (the login window does the same). Driven by a counter: bump it
/// on each failure. Callers skip the bump under Reduce Motion.
struct ShakeEffect: GeometryEffect {
    var travel: CGFloat = 8
    var shakes: CGFloat = 3
    var animatableData: CGFloat

    init(trigger: Int) {
        animatableData = CGFloat(trigger)
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        // Fractional part of the animated counter → 0…1 within one bump;
        // the sine dies out at both ends, so rest position is exact.
        let progress = animatableData - animatableData.rounded(.down)
        let offset = travel * sin(progress * .pi * 2 * shakes) * (1 - progress)
        return ProjectionTransform(CGAffineTransform(translationX: offset, y: 0))
    }
}

extension View {
    /// Shakes the view each time `trigger` changes (see ShakeEffect).
    func shake(trigger: Int) -> some View {
        modifier(ShakeEffect(trigger: trigger))
            .animation(.linear(duration: 0.4), value: trigger)
    }
}

/// Spinner that waits a beat before showing, so a fast load (a cache
/// miss that returns in ~100 ms) never flashes "Loading…" over the table.
struct DelayedProgressView: View {
    let title: LocalizedStringKey
    var delay: Duration = .milliseconds(250)
    @State private var isVisible = false

    var body: some View {
        ProgressView(title)
            .opacity(isVisible ? 1 : 0)
            .task {
                try? await Task.sleep(for: delay)
                withAnimation(.easeIn(duration: 0.2)) { isVisible = true }
            }
    }
}
