// MetalLibraryCompilerTool.swift

import Foundation

@main
struct MetalLibraryCompilerTool {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 6 else {
            throw MetalLibraryCompilerToolError.invalidArguments
        }
        let source = URL(fileURLWithPath: arguments[1])
        let output = URL(fileURLWithPath: arguments[2])
        let moduleCache = URL(fileURLWithPath: arguments[3], isDirectory: true)
        let providedMetalCompiler = URL(fileURLWithPath: arguments[4])
        let providedMetalLibraryCompiler = URL(fileURLWithPath: arguments[5])
        let toolchain = try MetalToolchainResolver().resolve(
            pluginMetalCompiler: providedMetalCompiler,
            pluginMetalLibraryCompiler: providedMetalLibraryCompiler
        )
        let workDirectory = output.deletingLastPathComponent()
        let airOutput = workDirectory.appendingPathComponent(
            "OpalCryptoSchnorrBatchVerification.air"
        )
        try FileManager.default.createDirectory(
            at: workDirectory,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: moduleCache,
            withIntermediateDirectories: true
        )

        var compileArguments = [
            "-c",
            source.path,
            "-o",
            airOutput.path,
            "-fmodules-cache-path=\(moduleCache.path)"
        ]
        if let systemRoot = ProcessInfo.processInfo.environment["SDKROOT"],
           !systemRoot.isEmpty {
            compileArguments.append(contentsOf: ["-isysroot", systemRoot])
        }
        try run(toolchain.metalCompiler, arguments: compileArguments)
        defer { try? FileManager.default.removeItem(at: airOutput) }
        try run(
            toolchain.metalLibraryCompiler,
            arguments: [airOutput.path, "-o", output.path]
        )
    }

    private static func run(
        _ executable: URL,
        arguments: [String]
    ) throws {
        #if os(macOS)
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw MetalLibraryCompilerToolError.compilationFailed
        }
        #else
        throw MetalLibraryCompilerToolError.compilationFailed
        #endif
    }
}
