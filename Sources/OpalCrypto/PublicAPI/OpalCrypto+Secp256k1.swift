// OpalCrypto+Secp256k1.swift

import Foundation

extension OpalCrypto {
    public enum Secp256k1 {
        public static func isPrivateKeyValid(_ privateKey: Data) -> Bool {
            StandardsForEfficientCryptography256k1CurveModel.Operation.isPrivateKeyData32BytesValid(privateKey)
        }

        public static func deriveCompressedPublicKey(from privateKey: Data) throws -> Data {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey,
                    format: .compressed
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func tweakAddPrivateKey(_ privateKey: Data, tweak: Data) throws -> Data {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .tweakAddPrivateKeyData32Bytes(
                        privateKey,
                        tweakData32Bytes: tweak
                    )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func tweakAddPublicKey(_ publicKey: Data, tweak: Data) throws -> Data {
            try validateTweakedPublicKeyInput(publicKey)
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Operation.tweakAddPublicKey(
                    publicKey,
                    tweakData32Bytes: tweak,
                    format: .compressed
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func deriveCompressedPublicKeys(from privateKeys: [Data]) async throws -> [Data] {
            do {
                return try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveCompressedPublicKeys(fromPrivateKeys32: privateKeys)
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func generatePrivateKey() throws -> Data {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .generatePrivateKeyData32Bytes()
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func deriveSharedSecret(
            privateKey: Data,
            publicKey: Data
        ) throws -> Data {
            try validatePrivateKey(privateKey)
            try validateSecp256k1PublicKey(publicKey)
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveSharedSecret(
                        privateKeyData32Bytes: privateKey,
                        publicKey: publicKey
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }
    }
}
