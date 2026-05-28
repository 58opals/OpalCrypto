// OpalCrypto.Key+WIF.swift

import Foundation
import OpalDiagnostics

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
                OpalDiagnostics.Field.operationField("wif_parse"),
                OpalDiagnostics.Field.formatField("wif"),
                OpalDiagnostics.Field.publicField("input_character_count", serialized.count)
            ]
            do {
                let decoded = try WalletImportFormatCodec.decode(serialized)
                self.privateKey = OpalCrypto.Secp256k1.PrivateKey(
                    validatedRawRepresentation: decoded.privateKey
                )
                self.isCompressed = decoded.isCompressed
            } catch let error as WalletImportFormatCodec.Error {
                let mappedError = Self.mapError(error)
                Self.recordFailed(
                    event: OpalDiagnostics.Event.wifParseFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
            Self.recordSucceeded(
                event: OpalDiagnostics.Event.wifParseSucceeded,
                fields: fields + [
                    OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                    OpalDiagnostics.Field.publicField("is_compressed", isCompressed)
                ]
            )
        }

        public func serialize() throws -> String {
            let fields = [
                OpalDiagnostics.Field.operationField("wif_serialize"),
                OpalDiagnostics.Field.formatField("wif"),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("is_compressed", isCompressed)
            ]
            do {
                let serialized = try WalletImportFormatCodec.encode(
                    privateKey: privateKey.rawRepresentation,
                    isCompressed: isCompressed
                )
                Self.recordSucceeded(
                    event: OpalDiagnostics.Event.wifSerializeSucceeded,
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("output_character_count", serialized.count)
                    ]
                )
                return serialized
            } catch let error as WalletImportFormatCodec.Error {
                let mappedError = Self.mapError(error)
                Self.recordFailed(
                    event: OpalDiagnostics.Event.wifSerializeFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
        }

        private static func recordSucceeded(
            event: OpalDiagnostics.Event,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: event,
                level: .opalCryptoDefault(for: event),
                fields: fields
            )
        }

        private static func recordFailed(
            event: OpalDiagnostics.Event,
            error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: event,
                level: .opalCryptoDefault(for: event),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private static func mapError(_ error: WalletImportFormatCodec.Error) -> Error {
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
    }
}
