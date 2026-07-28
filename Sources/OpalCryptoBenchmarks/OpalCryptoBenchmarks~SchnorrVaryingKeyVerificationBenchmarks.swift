// OpalCryptoBenchmarks~SchnorrVaryingKeyVerificationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func schnorrVaryingKeyVerificationBenchmarkCases() -> [BenchmarkCase] {
        [1024, 4096, 8192].flatMap { count in
            [
                BenchmarkCase(
                    name: "Metal Schnorr verify prep (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await metalSchnorrVaryingKeyPrepChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Metal Schnorr verify end-to-end (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await metalSchnorrVaryingKeyEndToEndChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Metal Schnorr verify warm (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .sync { _ in
                        try metalSchnorrVaryingKeyPreparedChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "CPU serial Schnorr verify (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .sync { _ in
                        try cpuVaryingKeySchnorrBatchSerialChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "CPU parallel Schnorr verify (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await cpuVaryingKeySchnorrBatchParallelChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "CPU parallel Schnorr verify end-to-end (varying keys, \(count))",
                    iterations: 1,
                    suites: [.hot, .metal],
                    operation: .asynchronous { _ in
                        try await cpuVaryingKeySchnorrBatchEndToEndChecksum(count: count)
                    }
                )
            ]
        }
    }

    private static func metalSchnorrVaryingKeyPrepChecksum(count: Int) async throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let input = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeyRawRepresentations: fixture.verificationKeyRawRepresentations
            )
        return varyingKeyMetalInputChecksum(input)
    }

    private static func metalSchnorrVaryingKeyEndToEndChecksum(count: Int) async throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let preparationStart = DispatchTime.now().uptimeNanoseconds
        let input = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeyRawRepresentations: fixture.verificationKeyRawRepresentations
            )
        let preparationNanoseconds = DispatchTime.now().uptimeNanoseconds - preparationStart
        return try MetalSchnorrVerificationCore.run(
            varyingKeyBatchInput: input,
            cpuPreparationNanoseconds: preparationNanoseconds
        )
    }

    private static func metalSchnorrVaryingKeyPreparedChecksum(count: Int) throws -> Int {
        try MetalSchnorrVerificationCore.run(
            varyingKeyBatchInput: try preparedMetalSchnorrVaryingKeyBatchInput(count: count)
        )
    }

    private static func cpuVaryingKeySchnorrBatchSerialChecksum(count: Int) throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let results = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKeys: fixture.verificationKeys
        )
        return try verificationChecksum(results: results, expected: fixture.expectedResults)
    }

    private static func cpuVaryingKeySchnorrBatchParallelChecksum(count: Int) async throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let results = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKeys: fixture.verificationKeys
        )
        return try verificationChecksum(results: results, expected: fixture.expectedResults)
    }

    private static func cpuVaryingKeySchnorrBatchEndToEndChecksum(
        count: Int
    ) async throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let results = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKeyRawRepresentations: fixture.verificationKeyRawRepresentations
        )
        return try verificationChecksum(results: results, expected: fixture.expectedResults)
    }

    private static func varyingKeyMetalInputChecksum(
        _ input: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput
    ) -> Int {
        var checksum = input.recordCount
        checksum ^= input.signatureXWords.count
        checksum ^= input.windowedNonAdjacentFormDigits.count
        checksum ^= input.sharedGeneratorTableWords.count
        checksum ^= input.varyingVerificationKeyTableWords.count
        for (index, result) in input.expectedResults.enumerated() {
            checksum ^= result == 1 ? index + 1 : -(index + 1)
        }
        return checksum
    }

    static func varyingKeySchnorrBatchFixture(
        count: Int
    ) throws -> SchnorrVaryingKeyCPUVerificationBatchFixture {
        guard let fixture = try schnorrVaryingKeyBatchFixture.cpuBatches[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return fixture
    }

    private static func preparedMetalSchnorrVaryingKeyBatchInput(
        count: Int
    ) throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        guard let input = try schnorrVaryingKeyBatchFixture.preparedMetalInputs[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return input
    }

}
