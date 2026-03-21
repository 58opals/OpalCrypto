// StandardsForEfficientCryptography256k1CurveModel.Operation~VerificationKey.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func makeVerificationKey(
        publicKey: Data
    ) throws -> VerificationKeyModel {
        VerificationKeyModel(
            parsedPublicKeyModel: try makeParsedPublicKey(publicKey: publicKey)
        )
    }

    static func makeVerificationKey(
        fromPrivateKeyData32Bytes privateKeyData32Bytes: Data
    ) throws -> VerificationKeyModel {
        let privateKeyScalar = try parsePrivateKeyScalar(
            privateKeyData32Bytes,
            requireNonZero: true
        )
        let publicPoint = ScalarMultiplicationModel.mulG(privateKeyScalar)
        guard let publicAffine = publicPoint.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return VerificationKeyModel(affinePoint: publicAffine)
    }

    static func tweakAddVerificationKey(
        _ verificationKeyModel: VerificationKeyModel,
        tweakScalar: ScalarModel
    ) throws -> VerificationKeyModel {
        VerificationKeyModel(
            parsedPublicKeyModel: try tweakAddParsedPublicKey(
                verificationKeyModel.parsedPublicKeyModel,
                tweakScalar: tweakScalar
            )
        )
    }
}
