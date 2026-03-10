// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "OpalCrypto",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .watchOS(.v26),
        .tvOS(.v26),
        .visionOS(.v26)
    ],
    products: [
        .library(
            name: "OpalCrypto",
            targets: ["OpalCrypto"]
        )
    ],
    targets: [
        .target(
            name: "OpalCrypto",
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "OpalCryptoTests",
            dependencies: ["OpalCrypto"]
        )
    ]
)
