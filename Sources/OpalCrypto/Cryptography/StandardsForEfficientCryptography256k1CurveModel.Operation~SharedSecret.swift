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
        let sharedPoint = ScalarMultiplicationModel.mul(privateKeyScalar, publicKeyAffine)
        guard let sharedAffine = sharedPoint.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return SecureHashAlgorithm256Model.hash(sharedAffine.encodeCompressed33())
    }
}
