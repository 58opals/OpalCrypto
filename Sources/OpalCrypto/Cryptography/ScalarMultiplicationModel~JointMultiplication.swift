// ScalarMultiplicationModel~JointMultiplication.swift

import Foundation

extension ScalarMultiplicationModel {
    static func mul(
        _ scalar: ScalarModel,
        _ verificationKeyModel: VerificationKeyModel
    ) -> JacobianPointModel {
        let scalarSplit = scalar.splitForEndomorphism()
        let primaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.firstScalar,
            width: verificationKeyWindowedNonAdjacentFormWidth
        )
        let secondaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.secondScalar,
            width: verificationKeyWindowedNonAdjacentFormWidth
        )

        return multiplyWindowedDigits(
            primaryDigits: primaryDigits,
            primaryTable: verificationKeyModel.oddMultiplesAffine,
            secondaryDigits: secondaryDigits,
            secondaryTable: verificationKeyModel.endomorphismOddMultiplesAffine
        )
    }

    static func mulJointGeneratorAndVerificationKey(
        generatorScalar: ScalarModel,
        verificationKeyScalar: ScalarModel,
        verificationKeyModel: VerificationKeyModel
    ) -> JacobianPointModel {
        let generatorSplit = generatorScalar.splitForEndomorphism()
        let verificationKeySplit = verificationKeyScalar.splitForEndomorphism()

        let generatorPrimaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            generatorSplit.firstScalar,
            width: generatorWindowedNonAdjacentFormWidth
        )
        let generatorSecondaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            generatorSplit.secondScalar,
            width: generatorWindowedNonAdjacentFormWidth
        )
        let verificationKeyPrimaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            verificationKeySplit.firstScalar,
            width: verificationKeyWindowedNonAdjacentFormWidth
        )
        let verificationKeySecondaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            verificationKeySplit.secondScalar,
            width: verificationKeyWindowedNonAdjacentFormWidth
        )

        let maximumDigitCount = max(
            generatorPrimaryDigits.count,
            generatorSecondaryDigits.count,
            verificationKeyPrimaryDigits.count,
            verificationKeySecondaryDigits.count
        )

        var result = JacobianPointModel.infinity
        for index in stride(from: maximumDigitCount - 1, through: 0, by: -1) {
            result = result.double()

            if index < generatorPrimaryDigits.count {
                result = addWindowedDigit(
                    generatorPrimaryDigits[index],
                    using: generatorOddMultiplesAffine,
                    to: result
                )
            }
            if index < generatorSecondaryDigits.count {
                result = addWindowedDigit(
                    generatorSecondaryDigits[index],
                    using: generatorEndomorphismOddMultiplesAffine,
                    to: result
                )
            }
            if index < verificationKeyPrimaryDigits.count {
                result = addWindowedDigit(
                    verificationKeyPrimaryDigits[index],
                    using: verificationKeyModel.oddMultiplesAffine,
                    to: result
                )
            }
            if index < verificationKeySecondaryDigits.count {
                result = addWindowedDigit(
                    verificationKeySecondaryDigits[index],
                    using: verificationKeyModel.endomorphismOddMultiplesAffine,
                    to: result
                )
            }
        }

        return result
    }

    static func multiplyWindowedDigits(
        primaryDigits: SignedScalar128Model.WindowedNonAdjacentForm,
        primaryTable: InlineArray<16, AffinePointModel>,
        secondaryDigits: SignedScalar128Model.WindowedNonAdjacentForm,
        secondaryTable: InlineArray<16, AffinePointModel>
    ) -> JacobianPointModel {
        let maximumDigitCount = max(primaryDigits.count, secondaryDigits.count)
        var result = JacobianPointModel.infinity
        for index in stride(from: maximumDigitCount - 1, through: 0, by: -1) {
            result = result.double()

            if index < primaryDigits.count {
                result = addWindowedDigit(
                    primaryDigits[index],
                    using: primaryTable,
                    to: result
                )
            }
            if index < secondaryDigits.count {
                result = addWindowedDigit(
                    secondaryDigits[index],
                    using: secondaryTable,
                    to: result
                )
            }
        }
        return result
    }
}
