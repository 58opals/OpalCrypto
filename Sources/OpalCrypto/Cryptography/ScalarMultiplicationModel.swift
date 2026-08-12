// ScalarMultiplicationModel.swift

import Foundation

enum ScalarMultiplicationModel {
    static func mul(_ scalar: ScalarModel, _ point: AffinePointModel) -> JacobianPointModel {
        let verificationKeyModel = VerificationKeyModel(affinePoint: point)
        return mul(scalar, verificationKeyModel)
    }

    static func mulWithDoubleAndAddLadder(
        _ scalar: ScalarModel,
        _ point: AffinePointModel
    ) -> JacobianPointModel {
        var resultZero = JacobianPointModel.infinity
        var resultOne = JacobianPointModel(affine: point)
        for index in stride(from: 255, through: 0, by: -1) {
            if scalar.isBitSet(at: index) {
                resultZero = resultZero.add(resultOne)
                resultOne = resultOne.double()
            } else {
                resultOne = resultZero.add(resultOne)
                resultZero = resultZero.double()
            }
        }
        return resultZero
    }
    
    @inlinable
    static func mulG(_ scalar: ScalarModel) -> JacobianPointModel {
        let split = scalar.splitForEndomorphism()
        let firstDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            split.firstScalar,
            width: generatorWindowedNonAdjacentFormWidth
        )
        let secondDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            split.secondScalar,
            width: generatorWindowedNonAdjacentFormWidth
        )

        return multiplyWindowedDigits(
            primaryDigits: firstDigits,
            primaryTable: generatorOddMultiplesAffine,
            secondaryDigits: secondDigits,
            secondaryTable: generatorEndomorphismOddMultiplesAffine
        )
    }
    
    @usableFromInline static let generator = AffinePointModel(
        x: FieldElementModel(unchecked: StandardsForEfficientCryptography256k1CurveModel.Constant.Gx),
        y: FieldElementModel(unchecked: StandardsForEfficientCryptography256k1CurveModel.Constant.Gy)
    )
}
