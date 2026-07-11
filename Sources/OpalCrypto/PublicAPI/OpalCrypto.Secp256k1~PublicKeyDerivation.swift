// OpalCrypto.Secp256k1~PublicKeyDerivation.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// Derives the compressed public key corresponding to `privateKey`.
    public static func derivePublicKey(from privateKey: PrivateKey) throws -> PublicKey {
        let fields = [
            OpalDiagnostics.Field.operationField("public_key_derive"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
            OpalDiagnostics.Field.inputLengthField(privateKey.rawRepresentation.count)
        ]
        do {
            let parsedPublicKeyModel = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .deriveParsedPublicKey(
                    fromPrivateKeyScalar: privateKey.scalarModel
                )
            let publicKey = PublicKey(
                parsedPublicKeyModel: parsedPublicKeyModel
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.publicKeyDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(publicKey.rawRepresentation.count)
                ]
            )
            return publicKey
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.publicKeyDeriveFailed, error: mappedError, fields: fields)
            throw mappedError
        } catch let error as Error {
            recordKeyOperationFailed(.publicKeyDeriveFailed, error: error, fields: fields)
            throw error
        }
    }

    /// Derives compressed public keys in input order.
    ///
    /// Cancellation is cooperative and throws ``CancellationError`` before returning partial output.
    public static func derivePublicKeys(from privateKeys: [PrivateKey]) async throws -> [PublicKey] {
        let fields = [
            OpalDiagnostics.Field.operationField("public_key_batch_derive"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("key_count", privateKeys.count),
            OpalDiagnostics.Field.publicField(
                "private_key_byte_count",
                privateKeys.first?.rawRepresentation.count ?? 0
            )
        ]
        do {
            let parsedPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel.Operation
                .deriveParsedPublicKeys(
                    fromValidatedPrivateKeys: privateKeys
                )
            try Task.checkCancellation()
            var publicKeys: [PublicKey] = .init()
            publicKeys.reserveCapacity(parsedPublicKeys.count)
            for (index, parsedPublicKey) in parsedPublicKeys.enumerated() {
                if index.isMultiple(of: 64) {
                    try Task.checkCancellation()
                }
                publicKeys.append(PublicKey(parsedPublicKeyModel: parsedPublicKey))
            }
            try Task.checkCancellation()
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.publicKeysDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeysDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("output_key_count", publicKeys.count)
                ]
            )
            try Task.checkCancellation()
            return publicKeys
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.publicKeysDeriveFailed, error: mappedError, fields: fields)
            throw mappedError
        } catch let error as Error {
            recordKeyOperationFailed(.publicKeysDeriveFailed, error: error, fields: fields)
            throw error
        }
    }
}
