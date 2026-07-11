// OpalCryptoBenchmarks.MetalValidation~GeneratedSchnorrCorpus.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks.MetalValidation {
    static func makeGeneratedSchnorrFixture() throws -> GeneratedSchnorrFixture {
        let privateKey = try makePrivateKey(lastByte: 1)
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(from: privateKey)
        var signatures: [OpalCrypto.Signature.Schnorr] = .init()
        var digests: [OpalCrypto.Signature.Digest] = .init()
        signatures.reserveCapacity(8192)
        digests.reserveCapacity(8192)

        for index in 0..<8192 {
            let originalDigest = try OpalCrypto.Signature.Digest(
                rawRepresentation: OpalCrypto.Hashing.sha256(
                    Data("opalcrypto-metal-validation-\(index)".utf8)
                )
            )
            let originalSignature = try OpalCrypto.Signature.Schnorr.sign(
                digest: originalDigest,
                privateKey: privateKey,
                noncePolicy: .bip340Deterministic
            )

            switch index % 32 {
            case 7:
                var corruptedDigest = originalDigest.rawRepresentation
                corruptedDigest[0] ^= 0x01
                digests.append(
                    try OpalCrypto.Signature.Digest(rawRepresentation: corruptedDigest)
                )
                signatures.append(originalSignature)
            case 15, 23:
                digests.append(originalDigest)
                signatures.append(try makeCanonicalCorruptedSignature(originalSignature))
            default:
                digests.append(originalDigest)
                signatures.append(originalSignature)
            }
        }
        return GeneratedSchnorrFixture(
            verificationKey: verificationKey,
            signatures: signatures,
            digests: digests
        )
    }

    static func validateGeneratedSchnorrCorpus(
        _ fixture: GeneratedSchnorrFixture
    ) throws -> Int {
        let tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
            verificationKey: fixture.verificationKey
        )
        let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: fixture.verificationKey
        )
        let expectedResults = cpuResults.map { $0 == 1 }
        let input = try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationBatchInput(
            signatures: fixture.signatures,
            digests: fixture.digests,
            expectedResults: expectedResults,
            verificationKey: fixture.verificationKey,
            tableWords: tableWords
        )
        let metalChecksum = try OpalCryptoBenchmarks.MetalSchnorrVerificationCore.run(
            batchInput: input
        )
        print("Metal generated Schnorr corpus: \(fixture.signatures.count)")
        return metalChecksum ^ checksum(cpuResults)
    }

    static func validateWrongVerificationKey(
        _ fixture: GeneratedSchnorrFixture
    ) throws -> Int {
        let wrongPrivateKey = try makePrivateKey(lastByte: 2)
        let wrongVerificationKey = try OpalCrypto.Signature.deriveVerificationKey(
            from: wrongPrivateKey
        )
        let tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
            verificationKey: wrongVerificationKey
        )

        let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: fixture.signatures,
            digests: fixture.digests,
            verificationKey: wrongVerificationKey
        )
        let input = try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationBatchInput(
            signatures: fixture.signatures,
            digests: fixture.digests,
            expectedResults: cpuResults.map { $0 == 1 },
            verificationKey: wrongVerificationKey,
            tableWords: tableWords
        )
        let metalChecksum = try OpalCryptoBenchmarks.MetalSchnorrVerificationCore.run(
            batchInput: input
        )
        print("Metal wrong-key Schnorr corpus: \(fixture.signatures.count)")
        return metalChecksum ^ checksum(cpuResults)
    }


    private static func makePrivateKey(
        lastByte: UInt8
    ) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data([UInt8](repeating: 0, count: 31) + [lastByte])
        )
    }


    private static func makeCanonicalCorruptedSignature(
        _ signature: OpalCrypto.Signature.Schnorr
    ) throws -> OpalCrypto.Signature.Schnorr {
        for byteIndex in stride(from: 63, through: 32, by: -1) {
            var bytes = signature.rawRepresentation
            bytes[byteIndex] ^= 0x01
            if let corrupted = try? OpalCrypto.Signature.Schnorr(
                rawRepresentation: bytes
            ) {
                return corrupted
            }
        }
        throw Error.unexpectedResult("could not construct canonical signature corruption")
    }

}
