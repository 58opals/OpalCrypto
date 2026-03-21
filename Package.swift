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
        ),
        .executable(
            name: "OpalCryptoBenchmarks",
            targets: ["OpalCryptoBenchmarks"]
        )
    ],
    targets: [
        .target(
            name: "OpalCrypto",
            resources: [
                .process("Resources")
            ]
        ),
        .executableTarget(
            name: "OpalCryptoBenchmarks",
            dependencies: ["OpalCrypto"]
        ),
        .testTarget(
            name: "OpalCryptoTests",
            dependencies: ["OpalCrypto"]
        )
    ]
)
