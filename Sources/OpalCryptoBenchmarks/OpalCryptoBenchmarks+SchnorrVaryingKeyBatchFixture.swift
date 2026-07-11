// OpalCryptoBenchmarks+SchnorrVaryingKeyBatchFixture.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    struct SchnorrVaryingKeyBatchFixture: Sendable {
        static let maximumCount = 8192
        private static let negativeCaseCountPerKind = 32

        let cpuBatches: [Int: SchnorrVaryingKeyCPUVerificationBatchFixture]
        let preparedMetalInputs: [
            Int: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput
        ]

        init() throws {
            var signatures: [OpalCrypto.Signature.Schnorr] = .init()
            signatures.reserveCapacity(Self.maximumCount)
            var digests: [OpalCrypto.Signature.Digest] = .init()
            digests.reserveCapacity(Self.maximumCount)
            var verificationKeys: [OpalCrypto.Signature.VerificationKey] = .init()
            verificationKeys.reserveCapacity(Self.maximumCount)

            for index in 0..<Self.maximumCount {
                let privateKey = try Self.makePrivateKey(index: index)
                let signingKey = privateKey.makeSigningKey()
                let digest = try OpalCrypto.Signature.Digest(
                    rawRepresentation: OpalCrypto.Hashing.sha256(
                        Data("opalcrypto-metal-schnorr-varying-\(index)".utf8)
                    )
                )
                signatures.append(try signingKey.signSchnorr(digest: digest))
                digests.append(digest)
                verificationKeys.append(signingKey.verificationKey)
            }

            var verificationSignatures = signatures
            var verificationDigests = digests
            var rotatedVerificationKeys = verificationKeys
            for offset in 0..<Self.negativeCaseCountPerKind {
                rotatedVerificationKeys[offset] = verificationKeys[offset + 1]

                let digestIndex = Self.negativeCaseCountPerKind + offset
                verificationDigests[digestIndex] = digests[digestIndex + 1]

                let signatureIndex = Self.negativeCaseCountPerKind * 2 + offset
                verificationSignatures[signatureIndex] = signatures[signatureIndex + 1]
            }

            let expectedResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: verificationSignatures,
                digests: verificationDigests,
                verificationKeys: rotatedVerificationKeys
            ).map { $0 == 1 }
            let negativeCaseCount = Self.negativeCaseCountPerKind * 3
            precondition(expectedResults.prefix(negativeCaseCount).allSatisfy { !$0 })
            precondition(expectedResults.dropFirst(negativeCaseCount).allSatisfy { $0 })

            var cpuBatches: [Int: SchnorrVaryingKeyCPUVerificationBatchFixture] = [:]
            var preparedMetalInputs: [
                Int: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput
            ] = [:]
            for count in [1024, 4096, 8192] {
                let cpuBatch = SchnorrVaryingKeyCPUVerificationBatchFixture(
                    signatures: Array(verificationSignatures.prefix(count)),
                    digests: Array(verificationDigests.prefix(count)),
                    verificationKeys: Array(rotatedVerificationKeys.prefix(count)),
                    publicKeys: Array(
                        rotatedVerificationKeys.prefix(count).map(\.publicKey)
                    ),
                    verificationKeyRawRepresentations: Array(
                        rotatedVerificationKeys.prefix(count).map(\.rawRepresentation)
                    ),
                    expectedResults: Array(expectedResults.prefix(count))
                )
                cpuBatches[count] = cpuBatch
                preparedMetalInputs[count] = try PerformanceBenchmarkOperations
                    .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                        signatures: cpuBatch.signatures,
                        digests: cpuBatch.digests,
                        expectedResults: cpuBatch.expectedResults,
                        verificationKeys: cpuBatch.verificationKeys
                    )
            }
            self.cpuBatches = cpuBatches
            self.preparedMetalInputs = preparedMetalInputs
        }

        private static func makePrivateKey(
            index: Int
        ) throws -> OpalCrypto.Secp256k1.PrivateKey {
            var rawRepresentation = Data(repeating: 0, count: 32)
            let scalar = UInt32(index + 1)
            rawRepresentation[28] = UInt8((scalar >> 24) & 0xff)
            rawRepresentation[29] = UInt8((scalar >> 16) & 0xff)
            rawRepresentation[30] = UInt8((scalar >> 8) & 0xff)
            rawRepresentation[31] = UInt8(scalar & 0xff)
            return try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: rawRepresentation
            )
        }
    }
}
