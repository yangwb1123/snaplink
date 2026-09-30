// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SnaplinkSSO",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SnaplinkSSO", targets: ["SnaplinkSSO"]),
    ],
    targets: [
        .target(
            name: "SnaplinkSSO",
            path: "sdks/swift/Sources"
        ),
        .testTarget(
            name: "SnaplinkSSOTests",
            dependencies: ["SnaplinkSSO"],
            path: "sdks/swift/Tests"
        ),
    ]
)
