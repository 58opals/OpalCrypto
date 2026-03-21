// PerformanceBenchmarkSupportModel.swift

import Foundation

package enum PerformanceBenchmarkSupportModel {
    package static func multiplyVerificationKey(
        scalarData32Bytes: Data,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Data {
        let scalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                scalarData32Bytes,
                requireNonZero: false
            )
        let point = ScalarMultiplicationModel.mul(
            scalar,
            verificationKey.verificationKeyModel
        )
        guard let affinePoint = point.convertToAffine() else {
            return Data()
        }
        return affinePoint.encodeCompressed33()
    }

    package static func jointMultiplyGeneratorAndVerificationKey(
        generatorScalarData32Bytes: Data,
        verificationKeyScalarData32Bytes: Data,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Data {
        let generatorScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                generatorScalarData32Bytes,
                requireNonZero: false
            )
        let verificationKeyScalar = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.parseTweakScalar(
                verificationKeyScalarData32Bytes,
                requireNonZero: false
            )
        let point = ScalarMultiplicationModel.mulJointGeneratorAndVerificationKey(
            generatorScalar: generatorScalar,
            verificationKeyScalar: verificationKeyScalar,
            verificationKeyModel: verificationKey.verificationKeyModel
        )
        guard let affinePoint = point.convertToAffine() else {
            return Data()
        }
        return affinePoint.encodeCompressed33()
    }
}
