// OpalCrypto+Secp256k1.swift

import Foundation

extension OpalCrypto {
    public enum Secp256k1 {
        public enum Error: Swift.Error, Equatable {
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPrivateKey
            case invalidPublicKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidPublicKey
            case invalidTweakLength(expected: Int, actual: Int)
            case invalidTweak
            case invalidDerivedKey
            case invalidSignatureLength(expected: Int, actual: Int)
            case invalidSignature
            case invalidDER
            case nonCanonicalDER
        }

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
            try validateCompressedPublicKey(publicKey)
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
