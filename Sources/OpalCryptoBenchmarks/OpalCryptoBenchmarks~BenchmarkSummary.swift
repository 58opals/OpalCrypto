// OpalCryptoBenchmarks~BenchmarkSummary.swift

import Foundation

extension OpalCryptoBenchmarks {
    private static let machineReadableNumberLocale = Locale(identifier: "en_US_POSIX")

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
}
