// OpalCrypto.Key+ExtendedPrivate.swift

import Foundation

extension OpalCrypto.Key {
    public struct ExtendedPrivate: Sendable, Equatable {

        internal let payload: ExtendedKeyPayloadModel
        internal let parsedPrivateKeyModel: ParsedPrivateKeyModel

        public var chainCode: ChainCode { try! ChainCode(rawRepresentation: payload.chainCode) }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Fingerprint { try! Fingerprint(rawRepresentation: payload.parentFingerprint) }
        public var childIndex: UInt32 { payload.childIndex }
        public var privateKey: OpalCrypto.Secp256k1.PrivateKey {
            try! OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: payload.keyData)
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
                OpalCryptoDiagnostics.operationField("extended_private_parse"),
                OpalCryptoDiagnostics.formatField("bip32_xprv"),
                OpalCryptoDiagnostics.publicField("input_character_count", serialized.count)
            ]
            do {
                let payload = try Self.makePayload(from: serialized)
                try self.init(payload: payload)
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.extendedPrivateParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.extendedPrivateParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields
            )
        }

        public static func root(seed: Seed) throws -> ExtendedPrivate {
            let fields = [
                OpalCryptoDiagnostics.operationField("extended_private_root"),
                OpalCryptoDiagnostics.formatField("bip32"),
                OpalCryptoDiagnostics.publicField("seed_byte_count", seed.rawRepresentation.count)
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
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.extendedPrivateRootFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            do {
                let rootKey = try ExtendedPrivate(payload: payload)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.extendedPrivateRootSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields
                )
                return rootKey
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.extendedPrivateRootFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
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
