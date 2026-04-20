// OpalCryptoBenchmarks.swift

import Foundation
import OpalCrypto

@main
enum OpalCryptoBenchmarks {
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
        let startNanoseconds = DispatchTime.now().uptimeNanoseconds
        var checksum = 0
        for _ in 0..<iterations {
            checksum ^= try operation()
        }
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startNanoseconds
        printSummary(
            name: name,
            iterations: iterations,
            elapsedNanoseconds: elapsedNanoseconds
        )
        return checksum
    }

    static func runAsyncBenchmark(
        name: String,
        iterations: Int,
        operation: @Sendable () async throws -> Int
    ) async rethrows -> Int {
        let startNanoseconds = DispatchTime.now().uptimeNanoseconds
        var checksum = 0
        for _ in 0..<iterations {
            checksum ^= try await operation()
        }
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startNanoseconds
        printSummary(
            name: name,
            iterations: iterations,
            elapsedNanoseconds: elapsedNanoseconds
        )
        return checksum
    }

    static func printSummary(
        name: String,
        iterations: Int,
        elapsedNanoseconds: UInt64
    ) {
        let totalMilliseconds = Double(elapsedNanoseconds) / 1_000_000
        let averageMicroseconds = Double(elapsedNanoseconds) / Double(iterations) / 1_000
        let totalText = totalMilliseconds.formatted(
            .number.precision(.fractionLength(3))
        )
        let averageText = averageMicroseconds.formatted(
            .number.precision(.fractionLength(3))
        )
        print("\(name): total \(totalText) ms, avg \(averageText) us")
    }
}
