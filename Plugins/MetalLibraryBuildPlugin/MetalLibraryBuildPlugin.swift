// MetalLibraryBuildPlugin.swift

import Foundation
import PackagePlugin

@main
struct MetalLibraryBuildPlugin: BuildToolPlugin {
    func createBuildCommands(
        context: PluginContext,
        target: Target
    ) async throws -> [Command] {
        let compiler = try context.tool(named: "MetalLibraryCompilerTool")
        let metalCompiler = try context.tool(named: "metal")
        let metalLibraryCompiler = metalCompiler.url
            .deletingLastPathComponent()
            .appending(path: "metallib")
        let source = target.directoryURL.appending(
            path: "MetalSchnorrBatchVerification.metal"
        )
        let output = context.pluginWorkDirectoryURL.appending(path: "default.metallib")
        let moduleCache = context.pluginWorkDirectoryURL.appending(
            path: "MetalModuleCache",
            directoryHint: .isDirectory
        )
        return [
            .buildCommand(
                displayName: "Compile OpalCrypto Schnorr Metal library",
                executable: compiler.url,
                arguments: [
                    source.path,
                    output.path,
                    moduleCache.path,
                    metalCompiler.url.path,
                    metalLibraryCompiler.path
                ],
                inputFiles: [source],
                outputFiles: [output]
            )
        ]
    }
}
