// MetalVaryingKeyVerificationLayoutValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Metal varying-key verification layout validation")
struct MetalVaryingKeyVerificationLayoutValidator {
    @Test("Serial and parallel preparation have exact ordered parity")
    func serialAndParallelPreparationHaveExactOrderedParity() async throws {
        let fixture = try makeFixture(recordCount: 256)

        let serialInput = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )
        let parallelInput = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )
        let rawKeyRepresentations = fixture.verificationKeys.map(\.rawRepresentation)
        let rawKeySerialInput = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeyRawRepresentations: rawKeyRepresentations
            )
        let rawKeyParallelInput = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeyRawRepresentations: rawKeyRepresentations
            )

        #expect(serialInput.recordCount == fixture.signatures.count)
        #expect(parallelInput.recordCount == serialInput.recordCount)
        #expect(parallelInput.signatureXWords == serialInput.signatureXWords)
        #expect(
            parallelInput.windowedNonAdjacentFormDigits
                == serialInput.windowedNonAdjacentFormDigits
        )
        #expect(
            parallelInput.sharedGeneratorTableWords
                == serialInput.sharedGeneratorTableWords
        )
        #expect(
            parallelInput.varyingVerificationKeyTableWords
                == serialInput.varyingVerificationKeyTableWords
        )
        #expect(parallelInput.expectedResults == serialInput.expectedResults)
        #expect(rawKeyParallelInput.signatureXWords == serialInput.signatureXWords)
        #expect(
            rawKeyParallelInput.windowedNonAdjacentFormDigits
                == serialInput.windowedNonAdjacentFormDigits
        )
        #expect(
            rawKeyParallelInput.varyingVerificationKeyTableWords
                == serialInput.varyingVerificationKeyTableWords
        )
        #expect(
            rawKeyParallelInput.varyingVerificationKeyTableWords
                == rawKeySerialInput.varyingVerificationKeyTableWords
        )
        #expect(serialInput.expectedResults.contains(0))
        #expect(serialInput.expectedResults.contains(1))
    }

    @Test("Adjacent records occupy adjacent verification-key table words")
    func adjacentRecordsOccupyAdjacentVerificationKeyTableWords() throws {
        let fixture = try makeFixture(recordCount: 4)
        let input = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )
        let sharedWordCount = PerformanceBenchmarkOperations
            .metalSchnorrSharedGeneratorTableWordCount
        let varyingSlotCount = PerformanceBenchmarkOperations
            .metalSchnorrVaryingVerificationKeyTableSlotCount

        #expect(input.sharedGeneratorTableWords.count == sharedWordCount)
        #expect(
            input.varyingVerificationKeyTableWords.count
                == fixture.signatures.count * varyingSlotCount
        )
        for recordIndex in fixture.verificationKeys.indices {
            let verificationKeyModel = fixture.verificationKeys[recordIndex]
                .verificationKeyModel
            let fullTableWords = PerformanceBenchmarkOperations
                .makeMetalSchnorrVerificationTableWords(
                    verificationKey: fixture.verificationKeys[recordIndex]
                )
            #expect(
                input.sharedGeneratorTableWords
                    == Array(fullTableWords.prefix(sharedWordCount))
            )
            let expectedVaryingWords = tableWords(
                verificationKeyModel.oddMultiplesAffine
            ) + tableWords(
                verificationKeyModel.endomorphismOddMultiplesAffine
            )
            #expect(expectedVaryingWords.count == varyingSlotCount)

            for slotIndex in 0..<varyingSlotCount {
                let offset = PerformanceBenchmarkOperations
                    .metalSchnorrVaryingVerificationKeyTableWordOffset(
                        recordIndex: recordIndex,
                        slotIndex: slotIndex,
                        recordCount: fixture.signatures.count
                    )
                #expect(
                    input.varyingVerificationKeyTableWords[offset]
                        == expectedVaryingWords[slotIndex]
                )
                if recordIndex + 1 < fixture.signatures.count {
                    let adjacentOffset = PerformanceBenchmarkOperations
                        .metalSchnorrVaryingVerificationKeyTableWordOffset(
                            recordIndex: recordIndex + 1,
                            slotIndex: slotIndex,
                            recordCount: fixture.signatures.count
                        )
                    #expect(adjacentOffset == offset + 1)
                }
            }
        }
    }

    @Test("Generator and varying-key components use their independent WNAF widths")
    func generatorAndVaryingKeyComponentsUseIndependentWidths() throws {
        let fixture = try makeFixture(recordCount: 4)
        let input = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )

        for recordIndex in fixture.signatures.indices {
            let signatureModel = fixture.signatures[recordIndex].signatureModel
            let signatureX = try FieldElementModel(data32: signatureModel.r)
            let signatureScalar = try ScalarModel(data32: signatureModel.s)
            let verificationKeyModel = fixture.verificationKeys[recordIndex]
                .verificationKeyModel
            let challenge = try ChallengeHashModel.makeChallengeScalar(
                digest32: fixture.digests[recordIndex].rawRepresentation,
                r: signatureX,
                verificationKeyModel: verificationKeyModel
            )
            let generatorSplit = signatureScalar.splitForEndomorphism()
            let verificationKeySplit = challenge.negateModN().splitForEndomorphism()

            expectPackedDigits(
                input.windowedNonAdjacentFormDigits,
                scalar: generatorSplit.firstScalar,
                width: 7,
                component: 0,
                recordIndex: recordIndex,
                recordCount: fixture.signatures.count
            )
            expectPackedDigits(
                input.windowedNonAdjacentFormDigits,
                scalar: generatorSplit.secondScalar,
                width: 7,
                component: 1,
                recordIndex: recordIndex,
                recordCount: fixture.signatures.count
            )
            expectPackedDigits(
                input.windowedNonAdjacentFormDigits,
                scalar: verificationKeySplit.firstScalar,
                width: 3,
                component: 2,
                recordIndex: recordIndex,
                recordCount: fixture.signatures.count
            )
            expectPackedDigits(
                input.windowedNonAdjacentFormDigits,
                scalar: verificationKeySplit.secondScalar,
                width: 3,
                component: 3,
                recordIndex: recordIndex,
                recordCount: fixture.signatures.count
            )
        }
    }

    @Test("Empty and single-record preparation preserve layout")
    func emptyAndSingleRecordPreparationPreserveLayout() async throws {
        let fixture = try makeFixture(recordCount: 1)
        let emptyInput = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: [],
                digests: [],
                expectedResults: [],
                verificationKeys: []
            )
        let parallelEmptyInput = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: [],
                digests: [],
                expectedResults: [],
                verificationKeys: []
            )

        #expect(emptyInput.recordCount == 0)
        #expect(emptyInput.signatureXWords.isEmpty)
        #expect(emptyInput.windowedNonAdjacentFormDigits.isEmpty)
        #expect(emptyInput.varyingVerificationKeyTableWords.isEmpty)
        #expect(emptyInput.expectedResults.isEmpty)
        #expect(
            emptyInput.sharedGeneratorTableWords.count
                == PerformanceBenchmarkOperations.metalSchnorrSharedGeneratorTableWordCount
        )
        #expect(parallelEmptyInput.signatureXWords == emptyInput.signatureXWords)
        #expect(
            parallelEmptyInput.windowedNonAdjacentFormDigits
                == emptyInput.windowedNonAdjacentFormDigits
        )
        #expect(
            parallelEmptyInput.varyingVerificationKeyTableWords
                == emptyInput.varyingVerificationKeyTableWords
        )

        let singleInput = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )
        let parallelSingleInput = try await PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: fixture.expectedResults,
                verificationKeys: fixture.verificationKeys
            )

        #expect(singleInput.recordCount == 1)
        #expect(singleInput.signatureXWords.count == 8)
        #expect(
            singleInput.windowedNonAdjacentFormDigits.count
                == PerformanceBenchmarkOperations.metalWindowedNonAdjacentFormComponentCount
                    * PerformanceBenchmarkOperations.metalWindowedNonAdjacentFormDigitCount
        )
        #expect(
            singleInput.varyingVerificationKeyTableWords.count
                == PerformanceBenchmarkOperations
                    .metalSchnorrVaryingVerificationKeyTableSlotCount
        )
        #expect(singleInput.expectedResults == [1])
        #expect(parallelSingleInput.signatureXWords == singleInput.signatureXWords)
        #expect(
            parallelSingleInput.windowedNonAdjacentFormDigits
                == singleInput.windowedNonAdjacentFormDigits
        )
        #expect(
            parallelSingleInput.varyingVerificationKeyTableWords
                == singleInput.varyingVerificationKeyTableWords
        )
        #expect(parallelSingleInput.expectedResults == singleInput.expectedResults)
    }

    private func makeFixture(recordCount: Int) throws -> (
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey],
        expectedResults: [Bool]
    ) {
        let signingKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(111 + $0).makeSigningKey()
        }
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-varying-key-\($0)")
        }
        let sourceSignatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: sourceDigests[$0])
        }
        let sourceVerificationKeys = signingKeys.map(\.verificationKey)
        let signatures = (0..<recordCount).map {
            sourceSignatures[$0 % sourceSignatures.count]
        }
        let digests = (0..<recordCount).map {
            sourceDigests[$0 % sourceDigests.count]
        }
        let verificationKeys = (0..<recordCount).map { index in
            let sourceIndex = index % sourceVerificationKeys.count
            return recordCount > 1 && index.isMultiple(of: 5)
                ? sourceVerificationKeys[(sourceIndex + 1) % sourceVerificationKeys.count]
                : sourceVerificationKeys[sourceIndex]
        }
        let expectedResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        ).map { $0 == 1 }

        return (signatures, digests, verificationKeys, expectedResults)
    }

    private func expectPackedDigits(
        _ packedDigits: [Int8],
        scalar: SignedScalar128Model,
        width: Int,
        component: Int,
        recordIndex: Int,
        recordCount: Int
    ) {
        let expectedDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalar,
            width: width
        )
        for digitIndex in 0..<PerformanceBenchmarkOperations
            .metalWindowedNonAdjacentFormDigitCount
        {
            let offset = PerformanceBenchmarkOperations
                .metalWindowedNonAdjacentFormPackedDigitOffset(
                    recordIndex: recordIndex,
                    component: component,
                    digitIndex: digitIndex,
                    recordCount: recordCount
                )
            let expectedDigit = digitIndex < expectedDigits.count
                ? expectedDigits[digitIndex]
                : 0
            #expect(packedDigits[offset] == expectedDigit)
        }
    }

    private func tableWords(
        _ table: InlineArray<16, AffinePointModel>
    ) -> [UInt32] {
        var words: [UInt32] = .init()
        words.reserveCapacity(
            PerformanceBenchmarkOperations
                .metalSchnorrVaryingVerificationKeyOddMultipleCount * 16
        )
        for index in 0..<PerformanceBenchmarkOperations
            .metalSchnorrVaryingVerificationKeyOddMultipleCount
        {
            words.append(contentsOf: littleEndianWords(table[index].x.data32Bytes))
            words.append(contentsOf: littleEndianWords(table[index].y.data32Bytes))
        }
        return words
    }

    private func littleEndianWords(_ data: Data) -> [UInt32] {
        precondition(data.count == 32)
        var words: [UInt32] = .init()
        words.reserveCapacity(8)
        for offset in stride(from: 28, through: 0, by: -4) {
            let word = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            words.append(word)
        }
        return words
    }
}
