// OpalCryptoBenchmarks~SignatureBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func signatureBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "ECDSA sign",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let signature = try OpalCrypto.Signature.ECDSA.sign(
                        message: context.ecdsaMessage,
                        privateKey: context.singlePrivateKey,
                        format: .der
                    )
                    return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "ECDSA verify",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let isValid = try context.ecdsaSignature.verify(
                        message: context.ecdsaMessage,
                        publicKey: context.compressedPublicKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "ECDSA verify (cached key)",
                iterations: 200,
                suites: [.smoke, .hot],
                operation: .sync { context in
                    let isValid = try context.ecdsaSignature.verify(
                        message: context.ecdsaMessage,
                        verificationKey: context.verificationKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Batch ECDSA verify digest (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    verificationChecksum(
                        try ecdsaDigestBatchResults(context: context, count: 256)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe ECDSA verify digest (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: ecdsaDigestBatchResults(context: context, count: 256),
                        seed: 0xec_d5_a2_56
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch ECDSA verify digest (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    verificationChecksum(
                        try ecdsaDigestBatchResults(context: context, count: 1024)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe ECDSA verify digest (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: ecdsaDigestBatchResults(context: context, count: 1024),
                        seed: 0xec_d5_a2_24
                    )
                }
            ),
            BenchmarkCase(
                name: "Schnorr sign",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let signature = try OpalCrypto.Signature.Schnorr.sign(
                        digest: context.schnorrDigest,
                        privateKey: context.singlePrivateKey,
                        noncePolicy: .bip340Deterministic
                    )
                    return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Schnorr verify",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let isValid = try context.schnorrSignature.verify(
                        digest: context.schnorrDigest,
                        publicKey: context.compressedPublicKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Schnorr verify (cached key)",
                iterations: 200,
                suites: [.smoke, .hot],
                operation: .sync { context in
                    let isValid = try context.schnorrSignature.verify(
                        digest: context.schnorrDigest,
                        verificationKey: context.verificationKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Batch Schnorr verify (cached key, 256)",
                iterations: 3,
                suites: [.hot, .metal],
                operation: .sync { context in
                    verificationChecksum(
                        try schnorrBatchResults(context: context, count: 256)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal Schnorr verify core (cached key, 256)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    try MetalSchnorrVerificationCore.run(
                        input: context.metalSchnorrVerificationInput,
                        count: 256
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe Schnorr verify (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: schnorrBatchResults(context: context, count: 256),
                        seed: 0x5c_40_22_56
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal Schnorr verify core (cached key, 1024)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    try MetalSchnorrVerificationCore.run(
                        input: context.metalSchnorrVerificationInput,
                        count: 1024
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch Schnorr verify (cached key, 1024)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    verificationChecksum(
                        try schnorrBatchResults(context: context, count: 1024)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe Schnorr verify (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: schnorrBatchResults(context: context, count: 1024),
                        seed: 0x5c_40_22_24
                    )
                }
            )
        ] + schnorrDistinctVerificationBenchmarkCases()
            + schnorrVaryingKeyVerificationBenchmarkCases()
            + schnorrProductionAPIBenchmarkCases()
    }

    private static func schnorrDistinctVerificationBenchmarkCases() -> [BenchmarkCase] {
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

    private static func schnorrVaryingKeyVerificationBenchmarkCases() -> [BenchmarkCase] {
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

    private static func schnorrProductionAPIBenchmarkCases() -> [BenchmarkCase] {
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

    static func metalThreadgroupWidthSweepBenchmarkCases() -> [BenchmarkCase] {
        guard let configuration = try? MetalSchnorrVerificationCore.configuration() else {
            return []
        }
        return configuration.supportedThreadgroupWidths.map { threadgroupWidth in
            BenchmarkCase(
                name: "Metal Schnorr threadgroup \(threadgroupWidth) (cached key, 8192)",
                iterations: 1,
                suites: [.metal],
                operation: .sync { _ in
                    try MetalSchnorrVerificationCore.run(
                        batchInput: try preparedMetalSchnorrBatchInput(count: 8192),
                        threadgroupWidth: threadgroupWidth
                    )
                }
            )
        }
    }

    private static func ecdsaDigestBatchResults(
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

    private static func schnorrBatchResults(
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

    private static func verificationChecksum(_ results: [Bool]) -> Int {
        var checksum = 0
        for (index, result) in results.enumerated() {
            checksum ^= result ? (index + 1) : 0
        }
        return checksum
    }

    private static func productionCachedKeyChecksum(
        count: Int,
        policy: OpalCrypto.BatchExecutionPolicy
    ) async throws -> Int {
        let fixture = try cpuSchnorrBatchFixture(count: count)
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: schnorrDistinctBatchFixture.verificationKey
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

    private static func verificationChecksum(
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

    private static func preparedMetalSchnorrBatchInput(
        count: Int
    ) throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        guard let input = schnorrDistinctBatchFixture.preparedMetalInputs[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return input
    }

    private static func cpuSchnorrBatchFixture(
        count: Int
    ) throws -> SchnorrCPUVerificationBatchFixture {
        guard let fixture = schnorrDistinctBatchFixture.cpuBatches[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return fixture
    }

    private static func varyingKeySchnorrBatchFixture(
        count: Int
    ) throws -> SchnorrVaryingKeyCPUVerificationBatchFixture {
        guard let fixture = schnorrVaryingKeyBatchFixture.cpuBatches[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return fixture
    }

    private static func preparedMetalSchnorrVaryingKeyBatchInput(
        count: Int
    ) throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        guard let input = schnorrVaryingKeyBatchFixture.preparedMetalInputs[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return input
    }

    private static let schnorrDistinctBatchFixture = try! SchnorrDistinctBatchFixture()
    private static let schnorrVaryingKeyBatchFixture = try! SchnorrVaryingKeyBatchFixture()
}
