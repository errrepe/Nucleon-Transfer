// Nucleon Transfer — borderless button with a hover highlight (polish
// pass 3). For the small glyph buttons (transfer row actions, banner
// close, path bar segments): flat at rest like `.borderless`, a soft
// rounded wash under the pointer and a deeper one while pressed.
// `.accessoryBarAction` was tried first, but on macOS 26 it draws a
// permanent bezel — too heavy for a banner or a Finder-style path bar.
import SwiftUI

struct HoverButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverButtonBody(configuration: configuration)
    }
}

private struct HoverButtonBody: View {
    let configuration: ButtonStyleConfiguration
    @State private var isHovered = false
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        configuration.label
            .padding(.horizontal, 3)
            .padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(.primary.opacity(washOpacity))
            )
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.4)
            .onHover { isHovered = $0 }
            .animation(Motion.adaptive(.easeOut(duration: 0.12), reduceMotion: reduceMotion), value: isHovered)
    }

    private var washOpacity: Double {
        guard isEnabled else { return 0 }
        if configuration.isPressed { return 0.16 }
        return isHovered ? 0.08 : 0
    }
}

extension ButtonStyle where Self == HoverButtonStyle {
    /// Borderless with a hover highlight — see HoverButtonStyle.
    static var hover: HoverButtonStyle { HoverButtonStyle() }
}
