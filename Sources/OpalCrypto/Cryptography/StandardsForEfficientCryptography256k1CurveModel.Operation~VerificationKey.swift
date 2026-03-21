// StandardsForEfficientCryptography256k1CurveModel.Operation~VerificationKey.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func makeVerificationKey(
        publicKey: Data
    ) throws -> VerificationKeyModel {
        do {
            return try VerificationKeyModel(publicKeyData: publicKey)
        } catch VerificationKeyModel.Error.invalidPublicKeyLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch {
            throw Error.invalidPublicKeyValue
        }
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
        let tweakPoint = ScalarMultiplicationModel.mulG(tweakScalar)
        let combined = JacobianPointModel(affine: verificationKeyModel.affinePoint).add(
            tweakPoint
        )
        guard let derivedAffine = combined.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return VerificationKeyModel(affinePoint: derivedAffine)
    }
}
