// OpalCrypto+Secp256k1.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Secp256k1 {
        public static func derivePublicKey(from privateKey: PrivateKey) throws -> PublicKey {
            let fields = [
                OpalDiagnostics.Field.operationField("public_key_derive"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.inputLengthField(privateKey.rawRepresentation.count)
            ]
            do {
                let publicKeyData = try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey.rawRepresentation,
                    format: .compressed
                )
                let publicKey = try PublicKey(validatingRawRepresentation: publicKeyData)
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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

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
                let tweakedPrivateKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .tweakAddPrivateKeyData32Bytes(
                        privateKey.rawRepresentation,
                        tweakData32Bytes: tweak.rawRepresentation
                    )
                let parsedPrivateKey = PrivateKey(validatedRawRepresentation: tweakedPrivateKey)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyTweakAddSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyTweakAddSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(parsedPrivateKey.rawRepresentation.count)
                    ]
                )
                return parsedPrivateKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyTweakAddFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyTweakAddFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

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
                let tweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation.tweakAddPublicKey(
                    publicKey.rawRepresentation,
                    tweakData32Bytes: tweak.rawRepresentation,
                    format: .compressed
                )
                let parsedPublicKey = try PublicKey(validatingRawRepresentation: tweakedPublicKey)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyTweakAddSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyTweakAddSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(parsedPublicKey.rawRepresentation.count)
                    ]
                )
                return parsedPublicKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyTweakAddFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyTweakAddFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyTweakAddFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyTweakAddFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

        public static func derivePublicKeys(from privateKeys: [PrivateKey]) async throws -> [PublicKey] {
            let fields = [
                OpalDiagnostics.Field.operationField("public_key_batch_derive"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.publicField("key_count", privateKeys.count)
            ]
            do {
                let publicKeys = try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveCompressedPublicKeys(fromPrivateKeys32: privateKeys.map(\.rawRepresentation))
                let parsedPublicKeys = try publicKeys.map(PublicKey.init(validatingRawRepresentation:))
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeysDeriveSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeysDeriveSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("output_key_count", parsedPublicKeys.count)
                    ]
                )
                return parsedPublicKeys
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeysDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeysDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeysDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeysDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

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
                        privateKeyData32Bytes: privateKey.rawRepresentation,
                        publicKey: publicKey.rawRepresentation
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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.sharedSecretDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.sharedSecretDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

    }
}
