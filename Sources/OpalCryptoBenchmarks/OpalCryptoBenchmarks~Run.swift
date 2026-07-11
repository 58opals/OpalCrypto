// OpalCryptoBenchmarks~Run.swift

import Foundation

extension OpalCryptoBenchmarks {
    static func run() async throws {
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
}
