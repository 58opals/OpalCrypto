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
    dependencies: [
        .package(url: "https://github.com/58opals/OpalDiagnostics.git", branch: "develop")
    ],
    targets: [
        .target(
            name: "OpalCrypto",
            dependencies: [
                .product(name: "OpalDiagnostics", package: "OpalDiagnostics")
            ],
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
            dependencies: [
                "OpalCrypto",
                .product(name: "OpalDiagnostics", package: "OpalDiagnostics")
            ]
        )
    ]
)
