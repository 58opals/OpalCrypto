// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "OpalCrypto",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .watchOS(.v27),
        .tvOS(.v27),
        .visionOS(.v27)
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
        .package(url: "https://github.com/58opals/OpalDiagnostics.git", revision: "4147c6191a4d25624c4f4f7e4e97eaeb8010a8fd")
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
