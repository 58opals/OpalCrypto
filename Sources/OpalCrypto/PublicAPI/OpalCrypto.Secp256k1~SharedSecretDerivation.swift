// OpalCrypto.Secp256k1~SharedSecretDerivation.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// Derives secp256k1 shared secrets for a private key and ordered candidate public keys.
    ///
    /// Each result is SHA-256 of the compressed shared EC point. The returned array preserves `publicKeys` ordering. Cancellation is cooperative and throws ``CancellationError`` before returning partial output.
    public static func deriveSharedSecrets(
        privateKey: PrivateKey,
        publicKeys: [PublicKey]
    ) async throws -> [SharedSecret] {
        let fields = [
            OpalDiagnostics.Field.operationField("shared_secret_batch_derive"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("public_key_count", publicKeys.count),
            OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
            OpalDiagnostics.Field.publicField(
                "public_key_byte_count",
                publicKeys.first?.rawRepresentation.count ?? 0
            )
        ]
        do {
            let sharedSecretData = try await StandardsForEfficientCryptography256k1CurveModel
                .Operation.deriveSharedSecrets(
                    privateKey: privateKey,
                    publicKeys: publicKeys
                )
            try Task.checkCancellation()
            var sharedSecrets: [SharedSecret] = .init()
            sharedSecrets.reserveCapacity(sharedSecretData.count)
            for (index, sharedSecretDatum) in sharedSecretData.enumerated() {
                if index.isMultiple(of: 64) {
                    try Task.checkCancellation()
                }
                sharedSecrets.append(SharedSecret(validatedRawRepresentation: sharedSecretDatum))
            }
            try Task.checkCancellation()
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.sharedSecretsDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretsDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("output_secret_count", sharedSecrets.count)
                ]
            )
            try Task.checkCancellation()
            return sharedSecrets
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.sharedSecretsDeriveFailed, error: mappedError, fields: fields)
            throw mappedError
        } catch let error as Error {
            recordKeyOperationFailed(.sharedSecretsDeriveFailed, error: error, fields: fields)
            throw error
        }
    }

    /// Derives SHA-256 of the compressed shared EC point.
    public static func deriveSharedSecret(
        privateKey: PrivateKey,
        publicKey: PublicKey
    ) throws -> SharedSecret {
        let fields = [
            OpalDiagnostics.Field.operationField("shared_secret_derive"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
            OpalDiagnostics.Field.publicField("public_key_byte_count", publicKey.rawRepresentation.count)
        ]
        do {
            let sharedSecret = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .deriveSharedSecret(
                    privateKeyScalar: privateKey.scalarModel,
                    publicKeyAffine: publicKey.parsedPublicKeyModel.affinePoint
                )
            let parsedSharedSecret = SharedSecret(validatedRawRepresentation: sharedSecret)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.sharedSecretDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(parsedSharedSecret.rawRepresentation.count)
                ]
            )
            return parsedSharedSecret
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.sharedSecretDeriveFailed, error: mappedError, fields: fields)
            throw mappedError
        } catch let error as Error {
            recordKeyOperationFailed(.sharedSecretDeriveFailed, error: error, fields: fields)
            throw error
        }
    }
}
