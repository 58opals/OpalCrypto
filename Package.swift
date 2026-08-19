// swift-tools-version: 6.4

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
                .product(name: "OpalDiagnostics", package: "OpalDiagnostics"),
                .target(
                    name: "OpalCryptoMetal",
                    condition: .when(platforms: [.macOS, .iOS, .tvOS, .visionOS])
                )
            ],
            resources: [
                .process("Resources")
            ]
        ),
        .target(
            name: "OpalCryptoMetal",
            exclude: [
                "MetalSchnorrBatchVerification.metal"
            ],
            resources: [
                .copy("Resources/MetalLibraryMarker.txt")
            ],
            plugins: [
                "MetalLibraryBuildPlugin"
            ]
        ),
        .executableTarget(
            name: "MetalLibraryCompilerTool",
            path: "Tools/MetalLibraryCompilerTool"
        ),
        .testTarget(
            name: "MetalLibraryCompilerToolTests",
            dependencies: ["MetalLibraryCompilerTool"]
        ),
        .plugin(
            name: "MetalLibraryBuildPlugin",
            capability: .buildTool(),
            dependencies: [
                "MetalLibraryCompilerTool"
            ]
        ),
        .executableTarget(
            name: "OpalCryptoBenchmarks",
            dependencies: [
                "OpalCrypto",
                .target(
                    name: "OpalCryptoMetal",
                    condition: .when(platforms: [.macOS, .iOS, .tvOS, .visionOS])
                )
            ]
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
