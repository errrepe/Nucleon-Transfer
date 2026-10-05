// swift-tools-version: 6.2
// Nucleon Transfer — release benchmark harness (F8.3-B0).
// Separate package (not part of the root test target): `NucleonCore` is a
// symlink to NucleonTransfer/NucleonTransfer/Core, compiled with
// -enable-testing so `nucleon-bench` can `@testable import` internal API.
// Run: swift run -c release --package-path Benchmarks nucleon-bench [filter]
import PackageDescription

let package = Package(
    name: "NucleonBenchmarks",
    platforms: [.macOS(.v26)],
    targets: [
        .target(
            name: "NucleonCore",
            path: "Sources/NucleonCore",
            swiftSettings: [.unsafeFlags(["-enable-testing"])]
        ),
        .executableTarget(
            name: "nucleon-bench",
            dependencies: ["NucleonCore"],
            path: "Sources/nucleon-bench"
        ),
    ]
)
