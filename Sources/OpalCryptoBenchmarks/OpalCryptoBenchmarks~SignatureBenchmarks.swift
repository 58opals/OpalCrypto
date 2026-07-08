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
                suites: [.hot],
                operation: .sync { context in
                    verificationChecksum(
                        try schnorrBatchResults(context: context, count: 256)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal Schnorr verify core (cached key, 256)",
                iterations: 1,
                suites: [.hot],
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
                suites: [.hot],
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
                suites: [.hot],
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
    }

    private static func schnorrDistinctVerificationBenchmarkCases() -> [BenchmarkCase] {
        [1024, 4096, 8192].flatMap { count in
            [
                BenchmarkCase(
                    name: "Metal Schnorr verify prep (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot],
                    operation: .sync { _ in
                        try metalSchnorrPrepChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Metal Schnorr verify end-to-end (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot],
                    operation: .sync { _ in
                        try metalSchnorrEndToEndChecksum(count: count)
                    }
                ),
                BenchmarkCase(
                    name: "Batch Schnorr verify distinct (cached key, \(count))",
                    iterations: 1,
                    suites: [.hot],
                    operation: .sync { _ in
                        try cpuDistinctSchnorrBatchChecksum(count: count)
                    }
                )
            ]
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

    private static func metalSchnorrEndToEndChecksum(count: Int) throws -> Int {
        let batchInput = try schnorrDistinctBatchInput(count: count)
        return try MetalSchnorrVerificationCore.run(batchInput: batchInput)
    }

    private static func metalSchnorrPrepChecksum(count: Int) throws -> Int {
        try schnorrDistinctBatchInput(count: count).checksum
    }

    private static func cpuDistinctSchnorrBatchChecksum(count: Int) throws -> Int {
        let fixture = schnorrDistinctBatchFixture
        precondition(count <= fixture.cases.count)

        var checksum = 0
        for (index, verificationCase) in fixture.cases.prefix(count).enumerated() {
            let result = try verificationCase.signature.verify(
                digest: verificationCase.digest,
                verificationKey: fixture.verificationKey
            )
            guard result == verificationCase.expected else {
                throw MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= result ? (index + 1) : -(index + 1)
        }
        return checksum
    }

    private static func schnorrDistinctBatchInput(
        count: Int
    ) throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        let fixture = schnorrDistinctBatchFixture
        precondition(count <= fixture.cases.count)

        var signatures: [OpalCrypto.Signature.Schnorr] = .init()
        signatures.reserveCapacity(count)
        var digests: [OpalCrypto.Signature.Digest] = .init()
        digests.reserveCapacity(count)
        var expectedResults: [Bool] = .init()
        expectedResults.reserveCapacity(count)

        for verificationCase in fixture.cases.prefix(count) {
            signatures.append(verificationCase.signature)
            digests.append(verificationCase.digest)
            expectedResults.append(verificationCase.expected)
        }

        return try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationBatchInput(
            signatures: signatures,
            digests: digests,
            expectedResults: expectedResults,
            verificationKey: fixture.verificationKey,
            tableWords: fixture.tableWords
        )
    }

    private static let schnorrDistinctBatchFixture = try! SchnorrDistinctBatchFixture()

    private struct SchnorrDistinctVerificationCase: Sendable {
        let digest: OpalCrypto.Signature.Digest
        let signature: OpalCrypto.Signature.Schnorr
        let expected: Bool
    }

    private struct SchnorrDistinctBatchFixture: Sendable {
        static let maximumCount = 8192

        let verificationKey: OpalCrypto.Signature.VerificationKey
        let cases: [SchnorrDistinctVerificationCase]
        let tableWords: [UInt32]

        init() throws {
            let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data([UInt8](repeating: 0x00, count: 31) + [0x01])
            )
            verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
                from: privateKey
            )

            var digests: [OpalCrypto.Signature.Digest] = .init()
            digests.reserveCapacity(Self.maximumCount)
            for index in 0..<Self.maximumCount {
                let message = Data("opalcrypto-metal-schnorr-\(index)".utf8)
                digests.append(
                    try OpalCrypto.Signature.Digest(
                        rawRepresentation: OpalCrypto.Hashing.sha256(message)
                    )
                )
            }

            var signatures: [OpalCrypto.Signature.Schnorr] = .init()
            signatures.reserveCapacity(Self.maximumCount)
            for digest in digests {
                signatures.append(
                    try OpalCrypto.Signature.Schnorr.sign(
                        digest: digest,
                        privateKey: privateKey,
                        noncePolicy: .bip340Deterministic
                    )
                )
            }

            var cases: [SchnorrDistinctVerificationCase] = .init()
            cases.reserveCapacity(Self.maximumCount)
            for index in 0..<Self.maximumCount {
                let shouldMismatchDigest = index % 16 == 15
                cases.append(
                    SchnorrDistinctVerificationCase(
                        digest: shouldMismatchDigest
                            ? digests[(index + 1) % Self.maximumCount]
                            : digests[index],
                        signature: signatures[index],
                        expected: !shouldMismatchDigest
                    )
                )
            }
            self.cases = cases
            tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
                verificationKey: verificationKey
            )
        }
    }
}
