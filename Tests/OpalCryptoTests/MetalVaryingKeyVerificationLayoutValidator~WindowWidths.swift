// MetalVaryingKeyVerificationLayoutValidator~WindowWidths.swift

import Foundation
import Testing
@testable import OpalCrypto

extension MetalVaryingKeyVerificationLayoutValidator {
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
}
