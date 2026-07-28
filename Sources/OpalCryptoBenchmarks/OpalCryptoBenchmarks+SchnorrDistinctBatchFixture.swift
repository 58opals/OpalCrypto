// OpalCryptoBenchmarks+SchnorrDistinctBatchFixture.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    struct SchnorrDistinctBatchFixture: Sendable {
        static let maximumCount = 8192

        let verificationKey: OpalCrypto.Signature.VerificationKey
        let tableWords: [UInt32]
        let cpuBatches: [Int: SchnorrCPUVerificationBatchFixture]
        let preparedMetalInputs: [Int: MetalSchnorrVerificationBatchBenchmarkInput]

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
                        noncePolicy: .bchDeterministic
                    )
                )
            }

            var verificationDigests = digests
            for index in 0..<Self.maximumCount {
                let shouldMismatchDigest = index % 16 == 15
                if shouldMismatchDigest {
                    verificationDigests[index] = digests[(index + 1) % Self.maximumCount]
                }
            }
            let expectedResults = try PerformanceBenchmarkOperations
                .verifySchnorrBatchSerial(
                    signatures: signatures,
                    digests: verificationDigests,
                    verificationKey: verificationKey
                )
                .map { $0 == 1 }
            let tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
                verificationKey: verificationKey
            )
            self.tableWords = tableWords

            var cpuBatches: [Int: SchnorrCPUVerificationBatchFixture] = [:]
            var preparedMetalInputs: [Int: MetalSchnorrVerificationBatchBenchmarkInput] = [:]
            for count in [1024, 4096, 8192] {
                let cpuBatch = SchnorrCPUVerificationBatchFixture(
                    signatures: Array(signatures.prefix(count)),
                    digests: Array(verificationDigests.prefix(count)),
                    expectedResults: Array(expectedResults.prefix(count))
                )
                cpuBatches[count] = cpuBatch
                preparedMetalInputs[count] = try PerformanceBenchmarkOperations
                    .makeMetalSchnorrVerificationBatchInput(
                        signatures: cpuBatch.signatures,
                        digests: cpuBatch.digests,
                        expectedResults: cpuBatch.expectedResults,
                        verificationKey: verificationKey,
                        tableWords: tableWords
                    )
            }
            self.cpuBatches = cpuBatches
            self.preparedMetalInputs = preparedMetalInputs
        }
    }
}
