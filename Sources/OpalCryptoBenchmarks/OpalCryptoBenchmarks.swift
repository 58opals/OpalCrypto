// OpalCryptoBenchmarks.swift

import Darwin
import Foundation
import OpalCrypto

@main
enum OpalCryptoBenchmarks {
    private static let machineReadableNumberLocale = Locale(identifier: "en_US_POSIX")

    nonisolated static func main() async {
        do {
            try await run()
        } catch let error as BenchmarkCommandError {
            fputs("Error: \(error.description)\n\n\(BenchmarkOptions.usage)\n", stderr)
            Darwin.exit(EXIT_FAILURE)
        } catch {
            fputs("Error: \(error)\n", stderr)
            Darwin.exit(EXIT_FAILURE)
        }
    }

    private static func run() async throws {
        let options = try BenchmarkOptions.parse(Array(CommandLine.arguments.dropFirst()))
        if options.shouldShowHelp {
            print(BenchmarkOptions.usage)
            return
        }

        if options.shouldValidateMetal {
            let checksum = try MetalValidation.run()
            print("Metal validation checksum: \(checksum)")
            return
        }

        let benchmarks = try selectedBenchmarks(options: options)
        if options.shouldList {
            for benchmark in benchmarks {
                print(benchmark.name)
            }
            return
        }

        let metalCoreConfiguration: MetalSchnorrVerificationCore.Configuration?
        if benchmarks.contains(where: \.usesMetalSchnorrVerificationCore) {
            metalCoreConfiguration = try MetalSchnorrVerificationCore.configuration()
        } else {
            metalCoreConfiguration = nil
        }
        let context = try BenchmarkContext.make()
        let metadata = BenchmarkRunMetadata.make(
            options: options,
            metalCoreConfiguration: metalCoreConfiguration
        )
        let reporter = try BenchmarkReporter(outputPath: options.outputPath)
        var checksum = 0

        print("OpalCryptoBenchmarks")
        print("Release-mode benchmark run")
        print("Suite: \(options.suite.rawValue)")
        if let filter = options.filter {
            print("Filter: \(filter)")
        }
        try reporter.recordRun(metadata)

        for benchmark in benchmarks {
            checksum ^= try await runBenchmark(
                benchmark,
                context: context,
                reporter: reporter,
                warmupIterations: options.warmupIterations,
                measurementSampleCount: options.measurementSampleCount
            )
        }

        print("Checksum: \(checksum)")
        try reporter.recordSummary(
            executedBenchmarkCount: benchmarks.count,
            checksum: checksum
        )
    }

    static func benchmarkCases() -> [BenchmarkCase] {
        publicKeyBenchmarks()
            + sharedSecretBenchmarks()
            + signatureBenchmarks()
            + keyDerivationBenchmarks()
            + encodingBenchmarks()
    }

    static func selectedBenchmarks(options: BenchmarkOptions) throws -> [BenchmarkCase] {
        var availableBenchmarks = benchmarkCases()
        if options.suite == .metal || options.suite == .full {
            let candidateSweepNames = [64, 128, 256, 512].map {
                "Metal Schnorr threadgroup \($0) (cached key, 8192)"
            }
            if candidateSweepNames.contains(where: options.filterMatches) {
                availableBenchmarks += metalThreadgroupWidthSweepBenchmarkCases()
            }
        }
        let selected = availableBenchmarks.filter { benchmark in
            benchmark.isIncluded(in: options.suite)
                && options.filterMatches(name: benchmark.name)
        }
        guard !selected.isEmpty else {
            throw BenchmarkCommandError.noMatchingBenchmarks
        }
        return selected
    }

    static func runBenchmark(
        _ benchmark: BenchmarkCase,
        context: BenchmarkContext,
        reporter: BenchmarkReporter,
        warmupIterations: Int,
        measurementSampleCount: Int
    ) async throws -> Int {
        switch benchmark.operation {
        case let .sync(operation):
            try runSyncBenchmark(
                name: benchmark.name,
                iterations: benchmark.iterations,
                reporter: reporter,
                warmupIterations: warmupIterations,
                measurementSampleCount: measurementSampleCount
            ) {
                try operation(context)
            }
        case let .asynchronous(operation):
            try await runAsyncBenchmark(
                name: benchmark.name,
                iterations: benchmark.iterations,
                reporter: reporter,
                warmupIterations: warmupIterations,
                measurementSampleCount: measurementSampleCount
            ) {
                try await operation(context)
            }
        }
    }

    static func runSyncBenchmark(
        name: String,
        iterations: Int,
        reporter: BenchmarkReporter,
        warmupIterations: Int,
        measurementSampleCount: Int,
        operation: () throws -> Int
    ) throws -> Int {
        validateMeasurementConfiguration(
            iterations: iterations,
            warmupIterations: warmupIterations,
            measurementSampleCount: measurementSampleCount
        )
        var checksum = 0
        MetalSchnorrVerificationCore.resetStageMeasurements()
        for _ in 0..<warmupIterations {
            _ = try operation()
        }
        MetalSchnorrVerificationCore.resetStageMeasurements()
        var samples: [UInt64] = .init()
        samples.reserveCapacity(measurementSampleCount)
        var metalStageSamples: [MetalSchnorrVerificationCore.StageMeasurement] = .init()
        metalStageSamples.reserveCapacity(measurementSampleCount)
        for _ in 0..<measurementSampleCount {
            let startNanoseconds = DispatchTime.now().uptimeNanoseconds
            var sampleChecksum = 0
            for _ in 0..<iterations {
                sampleChecksum ^= try operation()
            }
            samples.append(DispatchTime.now().uptimeNanoseconds - startNanoseconds)
            checksum ^= sampleChecksum
            if let stageSample = MetalSchnorrVerificationCore.StageMeasurement.combining(
                MetalSchnorrVerificationCore.takeStageMeasurements()
            ) {
                metalStageSamples.append(stageSample)
            }
        }
        precondition(
            metalStageSamples.isEmpty || metalStageSamples.count == samples.count,
            "Metal stage measurements must cover every benchmark sample."
        )
        try printSummary(
            name: name,
            iterations: iterations,
            samples: samples,
            metalStageSamples: metalStageSamples,
            reporter: reporter
        )
        return checksum
    }

    static func runAsyncBenchmark(
        name: String,
        iterations: Int,
        reporter: BenchmarkReporter,
        warmupIterations: Int,
        measurementSampleCount: Int,
        operation: @Sendable () async throws -> Int
    ) async throws -> Int {
        validateMeasurementConfiguration(
            iterations: iterations,
            warmupIterations: warmupIterations,
            measurementSampleCount: measurementSampleCount
        )
        var checksum = 0
        MetalSchnorrVerificationCore.resetStageMeasurements()
        for _ in 0..<warmupIterations {
            _ = try await operation()
        }
        MetalSchnorrVerificationCore.resetStageMeasurements()
        var samples: [UInt64] = .init()
        samples.reserveCapacity(measurementSampleCount)
        var metalStageSamples: [MetalSchnorrVerificationCore.StageMeasurement] = .init()
        metalStageSamples.reserveCapacity(measurementSampleCount)
        for _ in 0..<measurementSampleCount {
            let startNanoseconds = DispatchTime.now().uptimeNanoseconds
            var sampleChecksum = 0
            for _ in 0..<iterations {
                sampleChecksum ^= try await operation()
            }
            samples.append(DispatchTime.now().uptimeNanoseconds - startNanoseconds)
            checksum ^= sampleChecksum
            if let stageSample = MetalSchnorrVerificationCore.StageMeasurement.combining(
                MetalSchnorrVerificationCore.takeStageMeasurements()
            ) {
                metalStageSamples.append(stageSample)
            }
        }
        precondition(
            metalStageSamples.isEmpty || metalStageSamples.count == samples.count,
            "Metal stage measurements must cover every benchmark sample."
        )
        try printSummary(
            name: name,
            iterations: iterations,
            samples: samples,
            metalStageSamples: metalStageSamples,
            reporter: reporter
        )
        return checksum
    }

    static func printSummary(
        name: String,
        iterations: Int,
        samples: [UInt64],
        metalStageSamples: [MetalSchnorrVerificationCore.StageMeasurement],
        reporter: BenchmarkReporter
    ) throws {
        let sortedSamples = samples.sorted()
        let medianNanoseconds = sortedSamples[sortedSamples.count / 2]
        let minimumNanoseconds = sortedSamples[0]
        let medianMilliseconds = Double(medianNanoseconds) / 1_000_000
        let minimumMilliseconds = Double(minimumNanoseconds) / 1_000_000
        let medianAverageMicroseconds = Double(medianNanoseconds) / Double(iterations) / 1_000
        let medianText = fixedDecimal(medianMilliseconds)
        let minimumText = fixedDecimal(minimumMilliseconds)
        let averageText = fixedDecimal(medianAverageMicroseconds)
        print("\(name): median \(medianText) ms, min \(minimumText) ms, avg \(averageText) us")
        try reporter.recordBenchmark(
            BenchmarkResult(
                name: name,
                iterations: iterations,
                sampleCount: samples.count,
                samplesNanoseconds: samples,
                medianMilliseconds: medianMilliseconds,
                minimumMilliseconds: minimumMilliseconds,
                medianAverageMicroseconds: medianAverageMicroseconds,
                metalStageSamples: metalStageSamples
            )
        )
    }

    private static func fixedDecimal(_ value: Double) -> String {
        String(format: "%.3f", locale: machineReadableNumberLocale, value)
    }

    private static func validateMeasurementConfiguration(
        iterations: Int,
        warmupIterations: Int,
        measurementSampleCount: Int
    ) {
        precondition(iterations > 0, "Benchmark iterations must be positive.")
        precondition(warmupIterations > 0, "Benchmark warmup count must be positive.")
        precondition(measurementSampleCount > 0, "Benchmark sample count must be positive.")
    }
}

extension OpalCryptoBenchmarks {
    struct BenchmarkCase {
        enum Operation {
            case sync((BenchmarkContext) throws -> Int)
            case asynchronous(@Sendable (BenchmarkContext) async throws -> Int)
        }

        let name: String
        let iterations: Int
        let suites: [BenchmarkSuite]
        let operation: Operation

        func isIncluded(in suite: BenchmarkSuite) -> Bool {
            suite == .full || suites.contains(suite)
        }

        var usesMetalSchnorrVerificationCore: Bool {
            name.hasPrefix("Metal Schnorr verify core")
                || name.hasPrefix("Metal Schnorr verify end-to-end")
                || name.hasPrefix("Metal Schnorr verify warm")
                || name.hasPrefix("Metal Schnorr threadgroup")
        }
    }

    enum BenchmarkSuite: String, CaseIterable {
        case smoke
        case hot
        case metal
        case full

        static var allowedValuesText: String {
            allCases.map(\.rawValue).joined(separator: "|")
        }
    }

    struct BenchmarkOptions {
        static let defaultWarmupIterations = 1
        static let defaultMeasurementSampleCount = 3

        let suite: BenchmarkSuite
        let filter: String?
        let outputPath: String?
        let warmupIterations: Int
        let measurementSampleCount: Int
        let shouldList: Bool
        let shouldShowHelp: Bool
        let shouldValidateMetal: Bool

        static let usage = """
            Usage: OpalCryptoBenchmarks [--suite smoke|hot|metal|full] [--filter text] [--output path] [--warmups N] [--samples N] [--list] [--help]
                   OpalCryptoBenchmarks --validate-metal

            Options:
              --suite smoke|hot|metal|full  Select benchmark suite. Defaults to full.
              --filter text                 Run benchmark names containing text, case-insensitive.
              --output path                 Write JSONL records to path, creating parent directories.
              --warmups N                   Set positive warmup count. Defaults to 1.
              --samples N                   Set positive measurement sample count. Defaults to 3.
              --list                        Print selected benchmark names without running them.
              --validate-metal              Run Metal correctness validation. Must be used alone.
              --help                        Print this help text.
            """

        static func parse(_ arguments: [String]) throws -> BenchmarkOptions {
            let normalizedArguments = arguments.first == "--"
                ? Array(arguments.dropFirst())
                : arguments
            if let validationOptionIndex = normalizedArguments.firstIndex(
                of: "--validate-metal"
            ) {
                var conflictingArguments = normalizedArguments
                conflictingArguments.remove(at: validationOptionIndex)
                guard conflictingArguments.isEmpty else {
                    throw BenchmarkCommandError.metalValidationConflict(conflictingArguments)
                }
            }

            var suite: BenchmarkSuite = .full
            var filter: String?
            var outputPath: String?
            var warmupIterations = defaultWarmupIterations
            var measurementSampleCount = defaultMeasurementSampleCount
            var shouldList = false
            var shouldShowHelp = false
            var shouldValidateMetal = false

            var index = 0
            while index < normalizedArguments.count {
                let argument = normalizedArguments[index]
                switch argument {
                case "--suite":
                    let value = try value(
                        after: "--suite",
                        at: index,
                        in: normalizedArguments
                    )
                    index += 1
                    guard let parsedSuite = BenchmarkSuite(rawValue: value) else {
                        throw BenchmarkCommandError.unknownSuite(value)
                    }
                    suite = parsedSuite
                case "--filter":
                    filter = try value(after: "--filter", at: index, in: normalizedArguments)
                    index += 1
                case "--output":
                    outputPath = try value(after: "--output", at: index, in: normalizedArguments)
                    index += 1
                case "--warmups":
                    let value = try value(after: "--warmups", at: index, in: normalizedArguments)
                    warmupIterations = try positiveInteger(value, for: argument)
                    index += 1
                case "--samples":
                    let value = try value(after: "--samples", at: index, in: normalizedArguments)
                    measurementSampleCount = try positiveInteger(value, for: argument)
                    index += 1
                case "--list":
                    shouldList = true
                case "--validate-metal":
                    shouldValidateMetal = true
                case "--help", "-h":
                    shouldShowHelp = true
                default:
                    throw BenchmarkCommandError.unknownArgument(argument)
                }
                index += 1
            }

            return BenchmarkOptions(
                suite: suite,
                filter: filter,
                outputPath: outputPath,
                warmupIterations: warmupIterations,
                measurementSampleCount: measurementSampleCount,
                shouldList: shouldList,
                shouldShowHelp: shouldShowHelp,
                shouldValidateMetal: shouldValidateMetal
            )
        }

        func filterMatches(name: String) -> Bool {
            guard let filter else {
                return true
            }
            return name.localizedCaseInsensitiveContains(filter)
        }

        private static func value(
            after option: String,
            at index: Int,
            in arguments: [String]
        ) throws -> String {
            let valueIndex = index + 1
            guard valueIndex < arguments.count,
                  !arguments[valueIndex].hasPrefix("--") else {
                throw BenchmarkCommandError.missingValue(option)
            }
            return arguments[valueIndex]
        }

        private static func positiveInteger(
            _ value: String,
            for option: String
        ) throws -> Int {
            guard let integer = Int(value), integer > 0 else {
                throw BenchmarkCommandError.invalidPositiveInteger(option: option, value: value)
            }
            return integer
        }
    }

    enum BenchmarkCommandError: Error, CustomStringConvertible {
        case invalidPositiveInteger(option: String, value: String)
        case metalValidationConflict([String])
        case missingValue(String)
        case noMatchingBenchmarks
        case unknownArgument(String)
        case unknownSuite(String)

        var description: String {
            switch self {
            case let .invalidPositiveInteger(option, value):
                "Invalid value \(value) for \(option). Expected a positive integer."
            case let .metalValidationConflict(options):
                "--validate-metal must be used alone; remove \(options.joined(separator: ", "))."
            case let .missingValue(option):
                "Missing value for \(option)."
            case .noMatchingBenchmarks:
                "No benchmarks matched the selected suite and filter."
            case let .unknownArgument(argument):
                "Unknown argument \(argument)."
            case let .unknownSuite(suite):
                "Unknown suite \(suite). Expected one of \(BenchmarkSuite.allowedValuesText)."
            }
        }
    }

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

    struct BenchmarkResult {
        let name: String
        let iterations: Int
        let sampleCount: Int
        let samplesNanoseconds: [UInt64]
        let medianMilliseconds: Double
        let minimumMilliseconds: Double
        let medianAverageMicroseconds: Double
        let metalStageSamples: [MetalSchnorrVerificationCore.StageMeasurement]

        var jsonObject: [String: Any] {
            var object: [String: Any] = [
                "type": "benchmark",
                "name": name,
                "iterations": iterations,
                "sample_count": sampleCount,
                "samples_ns": samplesNanoseconds.map(Int64.init),
                "median_ms": medianMilliseconds,
                "min_ms": minimumMilliseconds,
                "median_avg_us": medianAverageMicroseconds
            ]
            if !metalStageSamples.isEmpty {
                object["metal_stage_samples"] = metalStageSamples.map(\.jsonObject)
            }
            return object
        }
    }

    final class BenchmarkReporter {
        private let fileHandle: FileHandle?

        init(outputPath: String?) throws {
            guard let outputPath else {
                fileHandle = nil
                return
            }

            let currentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            let outputURL = URL(fileURLWithPath: outputPath, relativeTo: currentDirectory)
                .standardizedFileURL
            let directoryURL = outputURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: nil
            )
            _ = FileManager.default.createFile(atPath: outputURL.path, contents: nil)
            fileHandle = try FileHandle(forWritingTo: outputURL)
        }

        deinit {
            try? fileHandle?.close()
        }

        func recordRun(_ metadata: BenchmarkRunMetadata) throws {
            try writeJSONLine(metadata.jsonObject)
        }

        func recordBenchmark(_ result: BenchmarkResult) throws {
            try writeJSONLine(result.jsonObject)
        }

        func recordSummary(
            executedBenchmarkCount: Int,
            checksum: Int
        ) throws {
            try writeJSONLine(
                [
                    "type": "benchmark_summary",
                    "executed_benchmark_count": executedBenchmarkCount,
                    "checksum": checksum
                ]
            )
        }

        private func writeJSONLine(_ object: [String: Any]) throws {
            let data = try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            )
            guard let line = String(data: data, encoding: .utf8) else {
                return
            }
            print(line)
            guard let fileHandle else {
                return
            }
            fileHandle.write(Data((line + "\n").utf8))
        }
    }

    private static func commandOutput(
        _ executablePath: String,
        arguments: [String]
    ) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return nil
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
        } catch {
            return nil
        }
    }
}
