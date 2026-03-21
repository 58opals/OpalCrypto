// StandardsForEfficientCryptography256k1CurveModel.Operation~ParsedPublicKey.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func makeParsedPublicKey(
        publicKey: Data
    ) throws -> ParsedPublicKeyModel {
        do {
            return try ParsedPublicKeyModel(publicKeyData: publicKey)
        } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch {
            throw Error.invalidPublicKeyValue
        }
    }

    static func tweakAddParsedPublicKey(
        _ parsedPublicKeyModel: ParsedPublicKeyModel,
        tweakScalar: ScalarModel
    ) throws -> ParsedPublicKeyModel {
        let tweakPoint = ScalarMultiplicationModel.mulG(tweakScalar)
        let combined = JacobianPointModel(affine: parsedPublicKeyModel.affinePoint).add(
            tweakPoint
        )
        guard let derivedAffine = combined.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return ParsedPublicKeyModel(affinePoint: derivedAffine)
    }
}
