// MetalVaryingKeyVerificationLayoutValidator~TableLayout.swift

import Foundation
import Testing
@testable import OpalCrypto

extension MetalVaryingKeyVerificationLayoutValidator {
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
