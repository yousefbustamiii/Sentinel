// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "sen",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.8.0"))
    ],
    targets: [
        .executableTarget(
            name: "sen",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "CryptoSwift"
            ]
        ),
        .testTarget(
            name: "senTests",
            dependencies: ["sen"]
        )
    ]
)
