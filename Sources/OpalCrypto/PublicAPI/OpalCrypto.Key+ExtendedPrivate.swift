// OpalCrypto.Key+ExtendedPrivate.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key {
    public struct ExtendedPrivate: Sendable, Equatable {

        internal let payload: ExtendedKeyPayloadModel
        internal let parsedPrivateKeyModel: ParsedPrivateKeyModel

        public var chainCode: ChainCode { try! ChainCode(rawRepresentation: payload.chainCode) }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Fingerprint { try! Fingerprint(rawRepresentation: payload.parentFingerprint) }
        public var childIndex: UInt32 { payload.childIndex }
        public var privateKey: OpalCrypto.Secp256k1.PrivateKey {
            OpalCrypto.Secp256k1.PrivateKey(validatedRawRepresentation: payload.keyData)
        }

        public var publicKey: ExtendedPublic {
            ExtendedPublic(
                depth: payload.depth,
                parentFingerprintUInt32BigEndian: payload.parentFingerprintUInt32BigEndian,
                childIndex: payload.childIndex,
                chainCode: payload.chainCode,
                parsedPublicKeyModel: parsedPrivateKeyModel.parsedPublicKeyModel
            )
        }

        public init(_ serialized: String) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("extended_private_parse"),
                OpalDiagnostics.Field.formatField("bip32_xprv"),
                OpalDiagnostics.Field.publicField("input_character_count", serialized.count)
            ]
            do {
                let payload = try Self.makePayload(from: serialized)
                try self.init(payload: payload)
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.extendedPrivateParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.extendedPrivateParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateParseSucceeded),
                fields: fields
            )
        }

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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.extendedPrivateRootFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateRootFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            do {
                let rootKey = try ExtendedPrivate(payload: payload)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.extendedPrivateRootSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateRootSucceeded),
                    fields: fields
                )
                return rootKey
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.extendedPrivateRootFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.extendedPrivateRootFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

        public func serialize() -> String {
            payload.serialize()
        }

        public func derived(indices: [UInt32]) throws -> ExtendedPrivate {
            var currentPayload = payload
            var currentParsedPrivateKeyModel = parsedPrivateKeyModel
            for index in indices {
                do {
                    let childMaterial = try ExtendedKeyDerivationModel
                        .derivePrivateChildMaterial(
                        from: currentPayload,
                        parsedPrivateKeyModel: currentParsedPrivateKeyModel,
                        index: index
                    )
                    currentPayload = childMaterial.payload
                    currentParsedPrivateKeyModel = childMaterial.parsedPrivateKeyModel
                } catch let error as ExtendedKeyDerivationModel.Error {
                    throw Self.mapDerivationError(error)
                }
            }
            return ExtendedPrivate(
                payload: currentPayload,
                parsedPrivateKeyModel: currentParsedPrivateKeyModel
            )
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

        private static func mapDerivationError(_ error: ExtendedKeyDerivationModel.Error) -> Error {
            switch error {
            case .depthOverflow:
                return .depthOverflow
            case .invalidSeed,
                 .invalidKeyKind,
                 .hardenedDerivationRequiresPrivateKey,
                 .invalidDerivedKey:
                return .invalidDerivedKey
            }
        }
    }
}
