// MetalVaryingKeyVerificationLayoutValidator~BoundaryLayout.swift

import Foundation
import Testing
@testable import OpalCrypto

extension MetalVaryingKeyVerificationLayoutValidator {
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
}
