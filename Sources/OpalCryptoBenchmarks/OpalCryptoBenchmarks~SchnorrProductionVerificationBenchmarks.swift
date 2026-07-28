// OpalCryptoBenchmarks~SchnorrProductionVerificationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func schnorrProductionAPIBenchmarkCases() -> [BenchmarkCase] {
        [1024, 4096, 8192].flatMap { count in
            [
                BenchmarkCase(
                    name: "Production API CPU Schnorr verify (cached key, \(count))",
                    iterations: 1,
                    suites: [.metal],
                    operation: .asynchronous { _ in
                        try await productionCachedKeyChecksum(
                            count: count,
                            policy: .cpu
                        )
                    }
                ),
                BenchmarkCase(
                    name: "Production API Metal Schnorr verify (cached key, \(count))",
                    iterations: 1,
                    suites: [.metal],
                    operation: .asynchronous { _ in
                        try await productionCachedKeyChecksum(
                            count: count,
                            policy: .metal
                        )
                    }
                ),
                BenchmarkCase(
                    name: "Production API CPU Schnorr verify (varying keys, \(count))",
                    iterations: 1,
                    suites: [.metal],
                    operation: .asynchronous { _ in
                        try await productionVaryingKeyChecksum(
                            count: count,
                            policy: .cpu
                        )
                    }
                ),
                BenchmarkCase(
                    name: "Production API Metal Schnorr verify (varying keys, \(count))",
                    iterations: 1,
                    suites: [.metal],
                    operation: .asynchronous { _ in
                        try await productionVaryingKeyChecksum(
                            count: count,
                            policy: .metal
                        )
                    }
                )
            ]
        }
    }

    private static func productionCachedKeyChecksum(
        count: Int,
        policy: OpalCrypto.BatchExecutionPolicy
    ) async throws -> Int {
        let fixture = try cpuSchnorrBatchFixture(count: count)
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: try schnorrDistinctBatchFixture.verificationKey
        )
        let results = try await batch.verify(using: policy)
        try validateProductionResults(
            results,
            expected: fixture.expectedResults
        )
        return verificationChecksum(results)
    }

    private static func productionVaryingKeyChecksum(
        count: Int,
        policy: OpalCrypto.BatchExecutionPolicy
    ) async throws -> Int {
        let fixture = try varyingKeySchnorrBatchFixture(count: count)
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: fixture.signatures,
            digests: fixture.digests,
            publicKeys: fixture.publicKeys
        )
        let results = try await batch.verify(using: policy)
        try validateProductionResults(
            results,
            expected: fixture.expectedResults
        )
        return verificationChecksum(results)
    }

    private static func validateProductionResults(
        _ results: [Bool],
        expected: [Bool]
    ) throws {
        guard results.count == expected.count else {
            throw MetalVerificationProbeError.invalidResult(index: results.count)
        }
        guard let mismatch = results.indices.first(where: {
            results[$0] != expected[$0]
        }) else {
            return
        }
        throw MetalVerificationProbeError.invalidResult(index: mismatch)
    }

}
