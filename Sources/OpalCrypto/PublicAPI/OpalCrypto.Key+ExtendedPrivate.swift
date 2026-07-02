// OpalCrypto.Key+ExtendedPrivate.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key {
    /// A BIP-32 extended private key.
    ///
    /// `ExtendedPrivate` is secret-bearing key material. It can derive child private keys and serialize to xprv text, so keep it behind explicit secret-access or signing/authoring boundaries.
    public struct ExtendedPrivate: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {

        internal let payload: ExtendedKeyPayloadModel
        internal let parsedPrivateKeyModel: ParsedPrivateKeyModel

        /// The BIP-32 chain code for this extended key.
        public var chainCode: ChainCode { try! ChainCode(rawRepresentation: payload.chainCode) }
        /// The BIP-32 depth.
        public var depth: UInt8 { payload.depth }
        /// The parent public-key fingerprint.
        public var parentFingerprint: Fingerprint { try! Fingerprint(rawRepresentation: payload.parentFingerprint) }
        /// The BIP-32 child index.
        public var childIndex: UInt32 { payload.childIndex }
        /// The secp256k1 private key contained by this extended private key.
        ///
        /// The returned private key is secret-bearing and should not be logged or stored outside an explicit secret boundary.
        public var privateKey: OpalCrypto.Secp256k1.PrivateKey {
            OpalCrypto.Secp256k1.PrivateKey(validatedRawRepresentation: payload.keyData)
        }

        /// An opaque signing capability for the contained secp256k1 private key.
        ///
        /// Prefer this value for signing workflows that do not need to export raw private-key bytes.
        public var signingKey: OpalCrypto.Secp256k1.SigningKey {
            OpalCrypto.Secp256k1.SigningKey(parsedPrivateKeyModel: parsedPrivateKeyModel)
        }

        /// The corresponding extended public key.
        ///
        /// The returned value contains only public derivation material. Access to this property still requires handling the secret-bearing receiver.
        public var publicKey: ExtendedPublic {
            ExtendedPublic(
                depth: payload.depth,
                parentFingerprintUInt32BigEndian: payload.parentFingerprintUInt32BigEndian,
                childIndex: payload.childIndex,
                chainCode: payload.chainCode,
                parsedPublicKeyModel: parsedPrivateKeyModel.parsedPublicKeyModel
            )
        }

        /// A redacted description that never includes xprv text, private key bytes, or chain code bytes.
        public var description: String {
            "OpalCrypto.Key.ExtendedPrivate(redacted, depth: \(depth), childIndex: \(childIndex))"
        }

        /// A redacted debug description that never includes xprv text, private key bytes, or chain code bytes.
        public var debugDescription: String {
            description
        }

        /// Parses a BIP-32 xprv string.
        ///
        /// `serialized` is secret-bearing input. Diagnostics record only public-safe metadata such as input character count, component byte counts, key kind, and error code.
        public init(_ serialized: String) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("extended_private_parse"),
                OpalDiagnostics.Field.formatField("bip32_xprv"),
                OpalDiagnostics.Field.publicField("input_character_count", serialized.count)
            ]
            let payload: ExtendedKeyPayloadModel
            do {
                payload = try Self.makePayload(from: serialized)
                try self.init(payload: payload)
            } catch let error as Error {
                Self.recordParseFailed(error, fields: fields)
                throw error
            }
            Self.recordParseSucceeded(fields: fields, payload: payload)
        }

        /// Derives the root extended private key for seed material.
        ///
        /// `seed` and the returned extended private key are secret-bearing. Diagnostics record only public-safe byte counts and error codes.
        public static func root(seed: Seed) throws -> ExtendedPrivate {
            let fields = [
                OpalDiagnostics.Field.operationField("extended_private_root"),
                OpalDiagnostics.Field.formatField("bip32"),
                OpalDiagnostics.Field.publicField("seed_byte_count", seed.rawRepresentation.count)
            ]
            let payload: ExtendedKeyPayloadModel
            do {
                payload = try ExtendedKeyDerivationModel.makeRootPrivateKey(
                    seed: seed.rawRepresentation
                )
            } catch let error as ExtendedKeyDerivationModel.Error {
                let mappedError: Error
                switch error {
                case .invalidSeed:
                    mappedError = Error.invalidSeedLength(actual: seed.rawRepresentation.count)
                case .invalidKeyKind,
                     .hardenedDerivationRequiresPrivateKey,
                     .depthOverflow,
                     .invalidDerivedKey:
                    mappedError = Error.invalidDerivedKey
                }
                recordRootFailed(mappedError, fields: fields)
                throw mappedError
            }
            do {
                let rootKey = try ExtendedPrivate(payload: payload)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.extendedPrivateRootSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateRootSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("private_key_byte_count", rootKey.payload.keyData.count),
                        OpalDiagnostics.Field.publicField("chain_code_byte_count", rootKey.payload.chainCode.count)
                    ]
                )
                return rootKey
            } catch let error as Error {
                recordRootFailed(error, fields: fields)
                throw error
            }
        }

        private static func recordRootFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.extendedPrivateRootFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateRootFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private static func recordParseSucceeded(
            fields: [OpalDiagnostics.Field],
            payload: ExtendedKeyPayloadModel
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.extendedPrivateParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("private_key_byte_count", payload.keyData.count),
                    OpalDiagnostics.Field.publicField("chain_code_byte_count", payload.chainCode.count)
                ]
            )
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.extendedPrivateParseFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateParseFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        /// Serializes this extended private key to BIP-32 xprv text.
        ///
        /// The returned string is secret-bearing and can reconstruct the extended private key.
        public func serialize() -> String {
            payload.serialize()
        }
        internal init(payload: ExtendedKeyPayloadModel) throws {
            guard payload.kind == .privateKey else {
                throw Error.invalidVersion(actual: ExtendedKeyPayloadModel.publicVersion)
            }
            self.payload = payload
            do {
                self.parsedPrivateKeyModel = try ParsedPrivateKeyModel(
                    privateKeyData32Bytes: payload.keyData
                )
            } catch {
                throw Error.invalidPrivateKey
            }
        }

        internal init(
            payload: ExtendedKeyPayloadModel,
            parsedPrivateKeyModel: ParsedPrivateKeyModel
        ) {
            self.payload = payload
            self.parsedPrivateKeyModel = parsedPrivateKeyModel
        }

        private static func makePayload(from serialized: String) throws -> ExtendedKeyPayloadModel {
            do {
                return try ExtendedKeyPayloadModel(serialized: serialized)
            } catch let error as ExtendedKeyPayloadModel.Error {
                throw mapPayloadError(error)
            }
        }

        private static func mapPayloadError(_ error: ExtendedKeyPayloadModel.Error) -> Error {
            switch error {
            case .invalidBase58:
                return .invalidBase58
            case .invalidChecksum:
                return .invalidChecksum
            case .invalidVersion(let actual):
                return .invalidVersion(actual: actual)
            case .invalidPayloadLength(let actual):
                return .invalidPayloadLength(expected: 78, actual: actual)
            case .invalidChainCodeLength(let actual):
                return .invalidChainCodeLength(expected: 32, actual: actual)
            case .invalidDepthMetadata:
                return .invalidDepthMetadata
            case .invalidPrivateKeyPrefix:
                return .invalidPrivateKey
            case .invalidPublicKeyLength,
                 .invalidPublicKeyPrefix,
                 .invalidPublicKey:
                return .invalidVersion(actual: ExtendedKeyPayloadModel.publicVersion)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            }
        }

    }
}
