// OpalCryptoBenchmarks~SignatureVerificationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func ecdsaDigestBatchResults(
        context: BenchmarkContext,
        count: Int
    ) throws -> [Bool] {
        var results: [Bool] = .init()
        results.reserveCapacity(count)
        for _ in 0..<count {
            try results.append(
                context.ecdsaSignature.verify(
                    digest: context.ecdsaDigest,
                    verificationKey: context.verificationKey
                )
            )
        }
        return results
    }

    static func schnorrBatchResults(
        context: BenchmarkContext,
        count: Int
    ) throws -> [Bool] {
        var results: [Bool] = .init()
        results.reserveCapacity(count)
        for _ in 0..<count {
            try results.append(
                context.schnorrSignature.verify(
                    digest: context.schnorrDigest,
                    verificationKey: context.verificationKey
                )
            )
        }
        return results
    }

    static func verificationChecksum(_ results: [Bool]) -> Int {
        var checksum = 0
        for (index, result) in results.enumerated() {
            checksum ^= result ? (index + 1) : 0
        }
        return checksum
    }

    static func verificationChecksum(
        results: [UInt32],
        expected: [Bool]
    ) throws -> Int {
        precondition(results.count == expected.count)
        var checksum = 0
        for index in results.indices {
            let expectedWord: UInt32 = expected[index] ? 1 : 0
            guard results[index] == expectedWord else {
                throw MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= results[index] == 1 ? index + 1 : -(index + 1)
        }
        return checksum
    }

}
