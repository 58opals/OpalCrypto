// OpalCrypto+Secp256k1.swift

import Foundation

extension OpalCrypto {
    public enum Secp256k1 {
        public static func derivePublicKey(from privateKey: PrivateKey) throws -> PublicKey {
            do {
                let publicKeyData = try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey.rawRepresentation,
                    format: .compressed
                )
                return try PublicKey(rawRepresentation: publicKeyData)
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
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
            do {
                let publicKeys = try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveCompressedPublicKeys(fromPrivateKeys32: privateKeys.map(\.rawRepresentation))
                return try publicKeys.map(PublicKey.init(rawRepresentation:))
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        public static func deriveSharedSecret(
            privateKey: PrivateKey,
            publicKey: PublicKey
        ) throws -> SharedSecret {
            do {
                let sharedSecret = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveSharedSecret(
                        privateKeyData32Bytes: privateKey.rawRepresentation,
                        publicKey: publicKey.rawRepresentation
                )
                return try SharedSecret(rawRepresentation: sharedSecret)
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }
    }
}
