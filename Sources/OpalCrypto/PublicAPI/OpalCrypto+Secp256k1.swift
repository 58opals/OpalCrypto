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
            try validateCompressedPublicKey(publicKey)
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

        public static func encodeDER(_ rawSignature: Data) throws -> Data {
            try makeSignature(rawSignature).encodeDistinguishedEncodingRules()
        }

        public static func decodeDER(_ derSignature: Data) throws -> Data {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Signature(
                    distinguishedEncodingRulesEncoded: derSignature
                ).raw64ByteSignatureData
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
                throw mapSignatureError(error)
            }
        }

        public static func normalizeLowS(_ rawSignature: Data) throws -> Data {
            try makeSignature(rawSignature).normalizeLowS().raw64ByteSignatureData
        }

        public static func isLowS(_ rawSignature: Data) throws -> Bool {
            try makeSignature(rawSignature).isLowS
        }

        private static func validateCompressedPublicKey(_ publicKey: Data) throws {
            guard publicKey.count == 33 else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
            }
            guard let prefix = publicKey.first else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
            }
            guard prefix == 0x02 || prefix == 0x03 else {
                throw Error.invalidPublicKeyPrefix(actual: prefix)
            }
        }

        private static func validateTweakedPublicKeyInput(_ publicKey: Data) throws {
            guard publicKey.count == 33 || publicKey.count == 65 else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
            }
            guard let prefix = publicKey.first else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
            }

            let isValidPrefix = switch publicKey.count {
            case 33:
                prefix == 0x02 || prefix == 0x03
            case 65:
                prefix == 0x04
            default:
                false
            }
            guard isValidPrefix else {
                throw Error.invalidPublicKeyPrefix(actual: prefix)
            }
        }

        private static func validatePrivateKey(_ privateKey: Data) throws {
            do {
                _ = try StandardsForEfficientCryptography256k1CurveModel.Operation.parsePrivateKeyScalar(
                    privateKey,
                    requireNonZero: true
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw mapOperationError(error)
            }
        }

        private static func makeSignature(_ rawSignature: Data) throws -> StandardsForEfficientCryptography256k1CurveModel.Signature {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.Signature(
                    raw64ByteSignatureData: rawSignature
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
                throw mapSignatureError(error)
            }
        }

        private static func mapOperationError(
            _ error: StandardsForEfficientCryptography256k1CurveModel.Operation.Error
        ) -> Error {
            switch error {
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKeyValue:
                return .invalidPrivateKey
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
            case .invalidPublicKeyValue:
                return .invalidPublicKey
            case .invalidTweakLength(let actual):
                return .invalidTweakLength(expected: 32, actual: actual)
            case .invalidTweakValue:
                return .invalidTweak
            case .invalidDerivedPrivateKey, .invalidDerivedPublicKey:
                return .invalidDerivedKey
            case .randomGenerationFailed(let status):
                return .randomGenerationFailed(status: status)
            }
        }

        private static func mapSignatureError(
            _ error: StandardsForEfficientCryptography256k1CurveModel.Error
        ) -> Error {
            switch error {
            case .invalidSignatureLength(let actual):
                return .invalidSignatureLength(expected: 64, actual: actual)
            case .signatureComponentZero, .invalidSignatureScalar:
                return .invalidSignature
            case .derMalformed:
                return .invalidDER
            case .derNonCanonical:
                return .nonCanonicalDER
            case .invalidDigestLength,
                 .invalidPrivateKeyLength,
                 .invalidPrivateKeyValue,
                 .invalidPublicKeyLength,
                 .randomGenerationFailed:
                return .invalidSignature
            }
        }
    }
}
