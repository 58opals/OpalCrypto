// OpalCryptoBenchmarks~SchnorrDistinctVerificationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func schnorrDistinctVerificationBenchmarkCases() -> [BenchmarkCase] {
        [1024, 4096, 8192].flatMap { count in
            [
                BenchmarkCase(
                    name: "Metal Schnorr verify prep (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await metalSchnorrPrepChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Metal Schnorr verify end-to-end (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await metalSchnorrEndToEndChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Metal Schnorr verify warm (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .sync { _ in
                        try metalSchnorrPreparedChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "CPU serial Schnorr verify (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .sync { _ in
                        try cpuDistinctSchnorrBatchSerialChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "CPU parallel Schnorr verify (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await cpuDistinctSchnorrBatchParallelChecksum(count: count)
                    }
                )
            ]
        }
    }

    private static func metalSchnorrEndToEndChecksum(count: Int) async throws -> Int {
        let preparationStart = DispatchTime.now().uptimeNanoseconds
        let batchInput = try await schnorrDistinctBatchInput(count: count)
        let preparationNanoseconds = DispatchTime.now().uptimeNanoseconds - preparationStart
        return try MetalSchnorrVerificationCore.run(
            batchInput: batchInput,
            cpuPreparationNanoseconds: preparationNanoseconds
        )
    }

    private static func metalSchnorrPrepChecksum(count: Int) async throws -> Int {
        try await schnorrDistinctBatchInput(count: count).checksum
    }

    private static func metalSchnorrPreparedChecksum(count: Int) throws -> Int {
        try MetalSchnorrVerificationCore.run(
            batchInput: try preparedMetalSchnorrBatchInput(count: count)
        )
    }

    private static func cpuDistinctSchnorrBatchSerialChecksum(count: Int) throws -> Int {
        let fixture = try cpuSchnorrBatchFixture(count: count)
        let results = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: schnorrDistinctBatchFixture.verificationKey
        )
        return try verificationChecksum(results: results, expected: fixture.expectedResults)
    }

    private static func cpuDistinctSchnorrBatchParallelChecksum(count: Int) async throws -> Int {
        let fixture = try cpuSchnorrBatchFixture(count: count)
        let results = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: schnorrDistinctBatchFixture.verificationKey
        )
        return try verificationChecksum(results: results, expected: fixture.expectedResults)
    }

    private static func schnorrDistinctBatchInput(
        count: Int
    ) async throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        let fixture = schnorrDistinctBatchFixture
        let cpuFixture = try cpuSchnorrBatchFixture(count: count)

        return try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVerificationBatchInputParallel(
                signatures: cpuFixture.signatures,
                digests: cpuFixture.digests,
                expectedResults: cpuFixture.expectedResults,
                verificationKey: fixture.verificationKey,
                tableWords: fixture.tableWords
            )
    }

    static func preparedMetalSchnorrBatchInput(
        count: Int
    ) throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        guard let input = schnorrDistinctBatchFixture.preparedMetalInputs[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return input
    }

}
