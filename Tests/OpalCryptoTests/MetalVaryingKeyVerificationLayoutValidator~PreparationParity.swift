// MetalVaryingKeyVerificationLayoutValidator~PreparationParity.swift

import Foundation
import Testing
@testable import OpalCrypto

extension MetalVaryingKeyVerificationLayoutValidator {
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
}
