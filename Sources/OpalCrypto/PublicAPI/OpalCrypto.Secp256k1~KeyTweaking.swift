// OpalCrypto.Secp256k1~KeyTweaking.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// Adds `tweak` to `privateKey` modulo the secp256k1 group order.
    public static func tweakAddPrivateKey(
        _ privateKey: PrivateKey,
        tweak: Scalar
    ) throws -> PrivateKey {
        let fields = [
            OpalDiagnostics.Field.operationField("private_key_tweak_add"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
            OpalDiagnostics.Field.publicField("tweak_byte_count", tweak.rawRepresentation.count)
        ]
        do {
            let tweakedPrivateKeyScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .tweakAddPrivateKey(
                    privateKey.scalarModel,
                    tweakScalar: tweak.scalarModel
                )
            let tweakedPrivateKey = PrivateKey(
                validatedScalarModel: tweakedPrivateKeyScalar
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyTweakAddSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyTweakAddSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(tweakedPrivateKey.rawRepresentation.count)
                ]
            )
            return tweakedPrivateKey
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.privateKeyTweakAddFailed, error: mappedError, fields: fields)
            throw mappedError
        }
    }

    /// Adds `tweak` times the generator to `publicKey`.
    public static func tweakAddPublicKey(
        _ publicKey: PublicKey,
        tweak: Scalar
    ) throws -> PublicKey {
        let fields = [
            OpalDiagnostics.Field.operationField("public_key_tweak_add"),
            OpalDiagnostics.Field.algorithmField("secp256k1"),
            OpalDiagnostics.Field.publicField("public_key_byte_count", publicKey.rawRepresentation.count),
            OpalDiagnostics.Field.publicField("tweak_byte_count", tweak.rawRepresentation.count)
        ]
        do {
            let tweakedPublicKeyModel = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .tweakAddParsedPublicKey(
                    publicKey.parsedPublicKeyModel,
                    tweakScalar: tweak.scalarModel
                )
            let tweakedPublicKey = PublicKey(parsedPublicKeyModel: tweakedPublicKeyModel)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.publicKeyTweakAddSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyTweakAddSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(tweakedPublicKey.rawRepresentation.count)
                ]
            )
            return tweakedPublicKey
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            let mappedError = mapOperationError(error)
            recordKeyOperationFailed(.publicKeyTweakAddFailed, error: mappedError, fields: fields)
            throw mappedError
        }
    }
}
