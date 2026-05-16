// OpalCrypto.Key+WIF.swift

import Foundation

extension OpalCrypto.Key {
    public struct WIF: Sendable, Equatable {

        public let privateKey: OpalCrypto.Secp256k1.PrivateKey
        public let isCompressed: Bool

        public init(
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            isCompressed: Bool = true
        ) {
            self.privateKey = privateKey
            self.isCompressed = isCompressed
        }

        public init(_ serialized: String) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("wif_parse"),
                OpalCryptoDiagnostics.formatField("wif"),
                OpalCryptoDiagnostics.publicField("input_character_count", serialized.count)
            ]
            do {
                let decoded = try WalletImportFormatCodecModel.decode(serialized)
                self.privateKey = try OpalCrypto.Secp256k1.PrivateKey(
                    rawRepresentation: decoded.privateKey
                )
                self.isCompressed = decoded.isCompressed
            } catch let error as WalletImportFormatCodecModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.wifParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = Self.mapSecp256k1Error(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.wifParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.wifParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.publicField("is_compressed", isCompressed)
                ]
            )
        }

        public func serialize() throws -> String {
            let fields = [
                OpalCryptoDiagnostics.operationField("wif_serialize"),
                OpalCryptoDiagnostics.formatField("wif"),
                OpalCryptoDiagnostics.publicField("is_compressed", isCompressed)
            ]
            do {
                let serialized = try WalletImportFormatCodecModel.encode(
                    privateKey: privateKey.rawRepresentation,
                    isCompressed: isCompressed
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.wifSerializeSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("output_character_count", serialized.count)
                    ]
                )
                return serialized
            } catch let error as WalletImportFormatCodecModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.wifSerializeFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        private static func mapError(_ error: WalletImportFormatCodecModel.Error) -> Error {
            switch error {
            case .invalidBase58:
                return .invalidBase58
            case .invalidChecksum:
                return .invalidChecksum
            case .invalidPayloadLength(let actual):
                return .invalidPayloadLength(actual: actual)
            case .invalidVersion(let actual):
                return .invalidVersion(actual: actual)
            case .invalidCompressionMarker(let actual):
                return .invalidCompressionMarker(actual: actual)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            }
        }

        private static func mapSecp256k1Error(_ error: OpalCrypto.Secp256k1.Error) -> Error {
            switch error {
            case .invalidPrivateKeyLength(let expected, let actual):
                return .invalidPrivateKeyLength(expected: expected, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidPublicKeyLength,
                 .invalidPublicKeyPrefix,
                 .invalidPublicKey,
                 .invalidTweakLength,
                 .invalidTweak,
                 .invalidDerivedKey,
                 .invalidSignatureLength,
                 .invalidSignature,
                 .invalidDER,
                 .nonCanonicalDER,
                 .randomGenerationFailed:
                return .invalidPrivateKey
            }
        }
    }
}
