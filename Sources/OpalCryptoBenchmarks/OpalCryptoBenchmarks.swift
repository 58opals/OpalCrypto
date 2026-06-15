// OpalCryptoBenchmarks.swift

import Foundation
import OpalCrypto

@main
enum OpalCryptoBenchmarks {
    private static let warmupIterations = 1
    private static let measurementSampleCount = 3
    private static let machineReadableNumberLocale = Locale(identifier: "en_US_POSIX")

    nonisolated static func main() async throws {
        let context = try BenchmarkContext.make()
        var checksum = 0

        print("OpalCryptoBenchmarks")
        print("Release-mode benchmark run")

        checksum ^= try await runPublicKeyBenchmarks(context: context)
        checksum ^= try runSignatureBenchmarks(context: context)
        checksum ^= try runKeyDerivationBenchmarks(context: context)
        checksum ^= try runEncodingBenchmarks(context: context)

        print("Checksum: \(checksum)")
    }

    static func runSyncBenchmark(
        name: String,
        iterations: Int,
        operation: () throws -> Int
    ) rethrows -> Int {
        validateMeasurementConfiguration(iterations: iterations)
        var checksum = 0
        for _ in 0..<warmupIterations {
            _ = try operation()
        }
        var samples: [UInt64] = .init()
        samples.reserveCapacity(measurementSampleCount)
        for _ in 0..<measurementSampleCount {
            let startNanoseconds = DispatchTime.now().uptimeNanoseconds
            var sampleChecksum = 0
            for _ in 0..<iterations {
                sampleChecksum ^= try operation()
            }
            samples.append(DispatchTime.now().uptimeNanoseconds - startNanoseconds)
            checksum ^= sampleChecksum
        }
        printSummary(
            name: name,
            iterations: iterations,
            samples: samples
        )
        return checksum
    }

    static func runAsyncBenchmark(
        name: String,
        iterations: Int,
        operation: @Sendable () async throws -> Int
    ) async rethrows -> Int {
        validateMeasurementConfiguration(iterations: iterations)
        var checksum = 0
        for _ in 0..<warmupIterations {
            _ = try await operation()
        }
        var samples: [UInt64] = .init()
        samples.reserveCapacity(measurementSampleCount)
        for _ in 0..<measurementSampleCount {
            let startNanoseconds = DispatchTime.now().uptimeNanoseconds
            var sampleChecksum = 0
            for _ in 0..<iterations {
                sampleChecksum ^= try await operation()
            }
            samples.append(DispatchTime.now().uptimeNanoseconds - startNanoseconds)
            checksum ^= sampleChecksum
        }
        printSummary(
            name: name,
            iterations: iterations,
            samples: samples
        )
        return checksum
    }

    static func printSummary(
        name: String,
        iterations: Int,
        samples: [UInt64]
    ) {
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
        print(
            """
            {"type":"benchmark","name":"\(jsonEscaped(name))","iterations":\(iterations),"samples":\(samples.count),"median_ms":\(medianText),"min_ms":\(minimumText),"median_avg_us":\(averageText)}
            """
        )
    }

    private static func fixedDecimal(_ value: Double) -> String {
        String(format: "%.3f", locale: machineReadableNumberLocale, value)
    }

    private static func validateMeasurementConfiguration(iterations: Int) {
        precondition(iterations > 0, "Benchmark iterations must be positive.")
        precondition(measurementSampleCount > 0, "Benchmark sample count must be positive.")
    }

    private static func jsonEscaped(_ value: String) -> String {
        var escaped = ""
        escaped.reserveCapacity(value.count)
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"":
                escaped += "\\\""
            case "\\":
                escaped += "\\\\"
            case "\u{08}":
                escaped += "\\b"
            case "\u{0C}":
                escaped += "\\f"
            case "\n":
                escaped += "\\n"
            case "\r":
                escaped += "\\r"
            case "\t":
                escaped += "\\t"
            case "\u{00}"..."\u{1F}":
                escaped += String(format: "\\u%04X", scalar.value)
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }
        return escaped
    }
}
