// OpalCryptoBenchmarks+BenchmarkRunMetadata.swift

import Foundation

extension OpalCryptoBenchmarks {
    struct BenchmarkRunMetadata {
        private static let schemaVersion = 2

        let runID: String
        let timestamp: String
        let gitSHA: String
        let gitBranch: String
        let swiftVersion: String
        let operatingSystem: String
        let architecture: String
        let buildConfiguration: String
        let suite: String
        let filter: String?
        let warmupIterations: Int
        let measurementSampleCount: Int
        let environment: BenchmarkRunEnvironment

        static func make(
            options: BenchmarkOptions,
            metalCoreConfiguration: MetalSchnorrVerificationCore.Configuration?
        ) -> BenchmarkRunMetadata {
            BenchmarkRunMetadata(
                runID: UUID().uuidString,
                timestamp: ISO8601DateFormatter().string(from: Date()),
                gitSHA: OpalCryptoBenchmarks.commandOutput(
                    "/usr/bin/env",
                    arguments: ["git", "rev-parse", "HEAD"]
                )
                    ?? "unknown",
                gitBranch: OpalCryptoBenchmarks.commandOutput(
                    "/usr/bin/env",
                    arguments: ["git", "branch", "--show-current"]
                ) ?? "unknown",
                swiftVersion: OpalCryptoBenchmarks.commandOutput(
                    "/usr/bin/env",
                    arguments: ["swift", "--version"]
                )
                    ?? "unknown",
                operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString,
                architecture: currentArchitecture,
                buildConfiguration: buildConfiguration,
                suite: options.suite.rawValue,
                filter: options.filter,
                warmupIterations: options.warmupIterations,
                measurementSampleCount: options.measurementSampleCount,
                environment: .make(metalCoreConfiguration: metalCoreConfiguration)
            )
        }

        var jsonObject: [String: Any] {
            var object: [String: Any] = [
                "type": "benchmark_run",
                "schema_version": Self.schemaVersion,
                "run_id": runID,
                "timestamp": timestamp,
                "git_sha": gitSHA,
                "git_branch": gitBranch,
                "swift_version": swiftVersion,
                "operating_system": operatingSystem,
                "architecture": architecture,
                "build_configuration": buildConfiguration,
                "suite": suite,
                "filter": filter ?? NSNull(),
                "warmup_iterations": warmupIterations,
                "measurement_sample_count": measurementSampleCount
            ]
            object.merge(environment.jsonObject) { _, environmentValue in environmentValue }
            return object
        }

        private static var currentArchitecture: String {
            #if arch(arm64)
            "arm64"
            #elseif arch(x86_64)
            "x86_64"
            #else
            "unknown"
            #endif
        }

        private static var buildConfiguration: String {
            #if DEBUG
            "debug"
            #else
            "release"
            #endif
        }
    }
}
