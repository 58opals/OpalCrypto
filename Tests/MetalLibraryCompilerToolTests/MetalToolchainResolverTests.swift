// MetalToolchainResolverTests.swift

import Foundation
import Testing
@testable import MetalLibraryCompilerTool

struct MetalToolchainResolverTests {
    @Test
    func componentToolchainHasPriority() throws {
        let component = toolchain(at: "/component")
        let legacy = toolchain(at: "/legacy")
        let plugin = toolchain(at: "/plugin")
        let resolver = makeResolver(
            component: component,
            legacy: [legacy],
            executableToolchains: [component, legacy, plugin]
        )

        let result = try resolver.resolve(
            pluginMetalCompiler: plugin.metalCompiler,
            pluginMetalLibraryCompiler: plugin.metalLibraryCompiler
        )

        #expect(result == component)
    }

    @Test
    func invalidPairsAreRejected() throws {
        let component = toolchain(at: "/component")
        let incompleteLegacy = toolchain(at: "/legacy")
        let plugin = toolchain(at: "/plugin")
        let resolver = MetalToolchainResolver(
            componentToolFinder: { name in
                name == "metal" ? component.metalCompiler : nil
            },
            legacyToolchainProvider: { [incompleteLegacy] },
            isExecutable: { url in
                url == component.metalCompiler
                    || url == incompleteLegacy.metalCompiler
                    || url == plugin.metalCompiler
                    || url == plugin.metalLibraryCompiler
            }
        )

        let result = try resolver.resolve(
            pluginMetalCompiler: plugin.metalCompiler,
            pluginMetalLibraryCompiler: plugin.metalLibraryCompiler
        )

        #expect(result == plugin)
    }

    @Test
    func legacyCryptexToolchainIsFirstFallback() throws {
        let legacy = toolchain(at: "/legacy")
        let plugin = toolchain(at: "/plugin")
        let resolver = makeResolver(
            legacy: [legacy],
            executableToolchains: [legacy, plugin]
        )

        let result = try resolver.resolve(
            pluginMetalCompiler: plugin.metalCompiler,
            pluginMetalLibraryCompiler: plugin.metalLibraryCompiler
        )

        #expect(result == legacy)
    }

    @Test
    func pluginToolchainIsFinalFallback() throws {
        let plugin = toolchain(at: "/plugin")
        let resolver = makeResolver(executableToolchains: [plugin])

        let result = try resolver.resolve(
            pluginMetalCompiler: plugin.metalCompiler,
            pluginMetalLibraryCompiler: plugin.metalLibraryCompiler
        )

        #expect(result == plugin)
    }

    @Test
    func unavailableToolchainReportsInstallationError() {
        let plugin = toolchain(at: "/plugin")
        let resolver = makeResolver()

        #expect(throws: MetalLibraryCompilerToolError.metalToolchainUnavailable) {
            try resolver.resolve(
                pluginMetalCompiler: plugin.metalCompiler,
                pluginMetalLibraryCompiler: plugin.metalLibraryCompiler
            )
        }
    }

    private func makeResolver(
        component: MetalToolchain? = nil,
        legacy: [MetalToolchain] = [],
        executableToolchains: [MetalToolchain] = []
    ) -> MetalToolchainResolver {
        let executablePaths = Set(
            executableToolchains.flatMap {
                [$0.metalCompiler.path, $0.metalLibraryCompiler.path]
            }
        )
        return MetalToolchainResolver(
            componentToolFinder: { name in
                switch name {
                case "metal": component?.metalCompiler
                case "metallib": component?.metalLibraryCompiler
                default: nil
                }
            },
            legacyToolchainProvider: { legacy },
            isExecutable: { executablePaths.contains($0.path) }
        )
    }

    private func toolchain(at directory: String) -> MetalToolchain {
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        return MetalToolchain(
            metalCompiler: root.appendingPathComponent("metal"),
            metalLibraryCompiler: root.appendingPathComponent("metallib")
        )
    }
}
