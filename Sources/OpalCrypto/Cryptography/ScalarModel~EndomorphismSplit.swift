// ScalarModel~EndomorphismSplit.swift

import Foundation

extension ScalarModel {
    func splitForEndomorphism() -> (firstScalar: SignedScalar128Model, secondScalar: SignedScalar128Model, isFirstNegative: Bool, isSecondNegative: Bool) {
        let coefficientOne = StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismCoefficientOne
        let coefficientTwo = StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismCoefficientTwo
        let minusBasisOne = StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismMinusBasisOne
        let minusBasisTwo = StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismMinusBasisTwo
        let lambda = ScalarModel(unchecked: StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismLambda)
        
        let coefficientOneProduct = ScalarModel(unchecked: value.multiplyShiftRight384(by: coefficientOne))
        let coefficientTwoProduct = ScalarModel(unchecked: value.multiplyShiftRight384(by: coefficientTwo))
        
        let minusBasisOneScalar = ScalarModel(unchecked: minusBasisOne)
        let minusBasisTwoScalar = ScalarModel(unchecked: minusBasisTwo)
        
        let secondScalar = coefficientOneProduct.mulModN(minusBasisOneScalar)
            .addModN(coefficientTwoProduct.mulModN(minusBasisTwoScalar))
        let firstScalar = subModN(secondScalar.mulModN(lambda))
        
        let signedFirstScalar = ScalarModel.makeSignedScalar128(from: firstScalar)
        let signedSecondScalar = ScalarModel.makeSignedScalar128(from: secondScalar)
        
        return (signedFirstScalar, signedSecondScalar, signedFirstScalar.isNegative, signedSecondScalar.isNegative)
    }
}

private extension ScalarModel {
    static func makeSignedScalar128(from scalar: ScalarModel) -> SignedScalar128Model {
        let isNegative = scalar.compare(to: StandardsForEfficientCryptography256k1CurveModel.halfOrderScalar) == .orderedDescending
        let magnitude = isNegative ? scalar.negateModN() : scalar
        return SignedScalar128Model(magnitude: magnitude.value, isNegative: isNegative)
    }
}

private extension Unsigned256BitIntegerModel {
    func multiplyShiftRight384(by other: Unsigned256BitIntegerModel) -> Unsigned256BitIntegerModel {
        var product = multiplyFullWidth(by: other)
        let roundingBit: UInt64 = 1 << 63
        let (roundedLimb, carryFromRounding) = product.limbs[5].addingReportingOverflow(roundingBit)
        product.limbs[5] = roundedLimb
        if carryFromRounding {
            let (limbSixSum, carryIntoLimbSeven) = product.limbs[6].addingReportingOverflow(1)
            product.limbs[6] = limbSixSum
            if carryIntoLimbSeven {
                product.limbs[7] &+= 1
            }
        }
        return Unsigned256BitIntegerModel(limbs: [product.limbs[6], product.limbs[7], 0, 0])
    }
}
