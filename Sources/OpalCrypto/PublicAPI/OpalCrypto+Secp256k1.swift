// OpalCrypto+Secp256k1.swift

import Foundation

extension OpalCrypto {
    public enum Secp256k1 {
        public static func derivePublicKey(from privateKey: PrivateKey) throws -> PublicKey {
            let fields = [
                OpalCryptoDiagnostics.operationField("public_key_derive"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.inputLengthField(privateKey.rawRepresentation.count)
            ]
            do {
                let publicKeyData = try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey.rawRepresentation,
                    format: .compressed
                )
                let publicKey = try PublicKey(rawRepresentation: publicKeyData)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeyDeriveSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(publicKey.rawRepresentation.count)
                    ]
                )
                return publicKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeyDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeyDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
        }

        public static func tweakAddPrivateKey(
            _ privateKey: PrivateKey,
            tweak: Scalar
        ) throws -> PrivateKey {
            do {
                let tweakedPrivateKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .tweakAddPrivateKeyData32Bytes(
                        privateKey.rawRepresentation,
                        tweakData32Bytes: tweak.rawRepresentation
                    )
                return try PrivateKey(rawRepresentation: tweakedPrivateKey)
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func tweakAddPublicKey(
            _ publicKey: PublicKey,
            tweak: Scalar
        ) throws -> PublicKey {
            do {
                let tweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation.tweakAddPublicKey(
                    publicKey.rawRepresentation,
                    tweakData32Bytes: tweak.rawRepresentation,
                    format: .compressed
                )
                return try PublicKey(rawRepresentation: tweakedPublicKey)
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func derivePublicKeys(from privateKeys: [PrivateKey]) async throws -> [PublicKey] {
            let fields = [
                OpalCryptoDiagnostics.operationField("public_key_batch_derive"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.publicField("key_count", privateKeys.count)
            ]
            do {
                let publicKeys = try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveCompressedPublicKeys(fromPrivateKeys32: privateKeys.map(\.rawRepresentation))
                let parsedPublicKeys = try publicKeys.map(PublicKey.init(rawRepresentation:))
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeysDeriveSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("output_key_count", parsedPublicKeys.count)
                    ]
                )
                return parsedPublicKeys
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeysDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeysDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
        }

        public static func deriveSharedSecret(
            privateKey: PrivateKey,
            publicKey: PublicKey
        ) throws -> SharedSecret {
            let fields = [
                OpalCryptoDiagnostics.operationField("shared_secret_derive"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("public_key_byte_count", publicKey.rawRepresentation.count)
            ]
            do {
                let sharedSecret = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveSharedSecret(
                        privateKeyData32Bytes: privateKey.rawRepresentation,
                        publicKey: publicKey.rawRepresentation
                )
                let parsedSharedSecret = try SharedSecret(rawRepresentation: sharedSecret)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.sharedSecretDeriveSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(parsedSharedSecret.rawRepresentation.count)
                    ]
                )
                return parsedSharedSecret
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = mapOperationError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.sharedSecretDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.sharedSecretDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
        }
    }
}
