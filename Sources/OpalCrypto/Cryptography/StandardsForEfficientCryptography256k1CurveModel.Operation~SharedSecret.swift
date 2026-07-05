// StandardsForEfficientCryptography256k1CurveModel.Operation~SharedSecret.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func generatePrivateKeyData32Bytes() throws -> Data {
        do {
            return try NonceGeneratorModel.makeSystemRandomScalar().data32Bytes
        } catch SchnorrSignatureModel.Error.randomGenerationFailed(let status) {
            throw Error.randomGenerationFailed(status: status)
        } catch {
            throw Error.invalidPrivateKeyValue
        }
    }

    static func deriveSharedSecret(
        privateKeyData32Bytes: Data,
        publicKey: Data
    ) throws -> Data {
        let privateKeyScalar = try parsePrivateKeyScalar(
            privateKeyData32Bytes,
            requireNonZero: true
        )
        let publicKeyAffine = try parsePublicKeyAffine(publicKey)
        return try deriveSharedSecret(
            privateKeyScalar: privateKeyScalar,
            publicKeyAffine: publicKeyAffine
        )
    }
}
