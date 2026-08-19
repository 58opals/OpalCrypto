// MetalToolchainResolver.swift

import Foundation

struct MetalToolchain: Equatable {
    let metalCompiler: URL
    let metalLibraryCompiler: URL
}

struct MetalToolchainResolver {
    typealias ComponentToolFinder = (String) -> URL?
    typealias LegacyToolchainProvider = () -> [MetalToolchain]
    typealias ExecutableValidator = (URL) -> Bool

    private let componentToolFinder: ComponentToolFinder
    private let legacyToolchainProvider: LegacyToolchainProvider
    private let isExecutable: ExecutableValidator

    init() {
        componentToolFinder = Self.findComponentTool(named:)
        legacyToolchainProvider = Self.legacyToolchains
        isExecutable = {
            FileManager.default.isExecutableFile(atPath: $0.path)
        }
    }

    init(
        componentToolFinder: @escaping ComponentToolFinder,
        legacyToolchainProvider: @escaping LegacyToolchainProvider,
        isExecutable: @escaping ExecutableValidator
    ) {
        self.componentToolFinder = componentToolFinder
        self.legacyToolchainProvider = legacyToolchainProvider
        self.isExecutable = isExecutable
    }

    func resolve(
        pluginMetalCompiler: URL,
        pluginMetalLibraryCompiler: URL
    ) throws -> MetalToolchain {
        if let componentToolchain = validatedToolchain(
            metalCompiler: componentToolFinder("metal"),
            metalLibraryCompiler: componentToolFinder("metallib")
        ) {
            return componentToolchain
        }

        if let legacyToolchain = legacyToolchainProvider().first(where: isValid) {
            return legacyToolchain
        }

        if let pluginToolchain = validatedToolchain(
            metalCompiler: pluginMetalCompiler,
            metalLibraryCompiler: pluginMetalLibraryCompiler
        ) {
            return pluginToolchain
        }

        throw MetalLibraryCompilerToolError.metalToolchainUnavailable
    }

    private func validatedToolchain(
        metalCompiler: URL?,
        metalLibraryCompiler: URL?
    ) -> MetalToolchain? {
        guard let metalCompiler, let metalLibraryCompiler else {
            return nil
        }
        let toolchain = MetalToolchain(
            metalCompiler: metalCompiler,
            metalLibraryCompiler: metalLibraryCompiler
        )
        return isValid(toolchain) ? toolchain : nil
    }

    private func isValid(_ toolchain: MetalToolchain) -> Bool {
        isExecutable(toolchain.metalCompiler)
            && isExecutable(toolchain.metalLibraryCompiler)
    }

    private static func findComponentTool(named name: String) -> URL? {
        #if os(macOS)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["--toolchain", "MetalToolchain", "--find", name]
        let standardOutput = Pipe()
        process.standardOutput = standardOutput
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        guard process.terminationStatus == 0 else {
            return nil
        }
        let data = standardOutput.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !output.isEmpty else {
            return nil
        }
        return URL(fileURLWithPath: output)
        #else
        return nil
        #endif
    }

    private static func legacyToolchains() -> [MetalToolchain] {
        let mountRoot = URL(
            fileURLWithPath: "/var/run/com.apple.security.cryptexd/mnt",
            isDirectory: true
        )
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: mountRoot,
            includingPropertiesForKeys: nil
        ) else {
            return []
        }
        return entries
            .filter { $0.lastPathComponent.hasPrefix("com.apple.MobileAsset.MetalToolchain-") }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
            .map { entry in
                let tools = entry.appendingPathComponent("Metal.xctoolchain/usr/bin")
                return MetalToolchain(
                    metalCompiler: tools.appendingPathComponent("metal"),
                    metalLibraryCompiler: tools.appendingPathComponent("metallib")
                )
            }
    }
}
