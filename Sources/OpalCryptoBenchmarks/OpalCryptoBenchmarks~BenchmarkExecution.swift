// OpalCryptoBenchmarks~BenchmarkExecution.swift

import Foundation

extension OpalCryptoBenchmarks {
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
