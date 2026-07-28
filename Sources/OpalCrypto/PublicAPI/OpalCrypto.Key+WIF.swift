// OpalCrypto.Key+WIF.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key {
    /// A Wallet Import Format wrapper for a secp256k1 private key.
    ///
    /// `WIF` is secret-bearing key material. Serialized WIF text can reconstruct the private key and should only cross explicit secret-access or import/export boundaries.
    public struct WIF: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {

        /// The private key encoded by this WIF value.
        ///
        /// This value is secret-bearing.
        public let privateKey: OpalCrypto.Secp256k1.PrivateKey
        /// Whether the WIF encodes a compressed public-key preference.
        public let isCompressed: Bool

        /// Creates a WIF wrapper for private key export.
        ///
        /// `privateKey` is secret-bearing. Diagnostics are emitted only by parsing and serialization operations, not by this wrapper initializer.
        public init(
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            isCompressed: Bool = true
        ) {
            self.privateKey = privateKey
            self.isCompressed = isCompressed
        }

        /// Creates an opaque signing capability for the private key encoded by this WIF value.
        ///
        /// Prefer the returned `SigningKey` for signing workflows that do not need to export raw private-key bytes.
        public func makeSigningKey() -> OpalCrypto.Secp256k1.SigningKey {
            privateKey.makeSigningKey()
        }

        /// A redacted description that never includes WIF text or private key bytes.
        public var description: String {
            "OpalCrypto.Key.WIF(redacted, isCompressed: \(isCompressed), privateKeyByteCount: \(privateKey.rawRepresentation.count))"
        }

        /// A redacted debug description that never includes WIF text or private key bytes.
        public var debugDescription: String {
            description
        }

        /// Parses serialized Wallet Import Format text.
        ///
        /// `serialized` is secret-bearing input. Diagnostics record only public-safe metadata such as input character count, compression flag, private key byte count, and error code.
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

        /// Serializes this value to Wallet Import Format text.
        ///
        /// The returned string is secret-bearing and can reconstruct the private key.
        public func serialize() -> String {
            let fields = [
                OpalDiagnostics.Field.operationField("wif_serialize"),
                OpalDiagnostics.Field.formatField("wif"),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("is_compressed", isCompressed)
            ]
            let serialized = WalletImportFormatCodec.encode(
                privateKey: privateKey,
                isCompressed: isCompressed
            )
            Self.recordSucceeded(
                event: OpalDiagnostics.Event.wifSerializeSucceeded,
                fields: fields + [
                    OpalDiagnostics.Field.publicField("output_character_count", serialized.count)
                ]
            )
            return serialized
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
            case .payloadLengthExceedsMaximum(let maximum):
                return .payloadLengthExceedsMaximum(maximum: maximum)
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
