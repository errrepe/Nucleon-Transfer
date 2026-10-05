// Nucleon Transfer — drop-target overlay for the folder table (F7 S3.1).
// Drawn while a file drag hovers over a writable folder: tint stroke +
// 6% accent wash + a regular-material capsule naming the destination.
// Purely decorative — hit testing is off so the drop still lands on the
// table underneath. Polish pass: the capsule's destination name
// crossfades as the drag crosses folder rows instead of snapping.
import SwiftUI

struct DropOverlay: View {
    /// The folder the drop would upload into (its name labels the capsule).
    let location: DriveLocation

    var body: some View {
        RoundedRectangle(cornerRadius: 10)
            .strokeBorder(.tint, lineWidth: 2)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color.accentColor.opacity(0.06))
            )
            .overlay {
                Text("Drop to upload to “\(location.name)”")
                    .font(.callout)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(.regularMaterial, in: Capsule())
                    .contentTransition(.opacity)
                    .animation(.snappy(duration: 0.2), value: location)
            }
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

#Preview("Drop Overlay") {
    DropOverlay(location: DriveLocation(
        shareID: "share-main", linkID: "link-projects", name: "Projects"
    ))
    .frame(width: 480, height: 320)
    .padding()
}
