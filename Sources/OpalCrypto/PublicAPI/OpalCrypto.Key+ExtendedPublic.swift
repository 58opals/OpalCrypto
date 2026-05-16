// OpalCrypto.Key+ExtendedPublic.swift

import Foundation

extension OpalCrypto.Key {
    public struct ExtendedPublic: Sendable, Equatable {

        internal let payload: ExtendedKeyPayloadModel
        internal let parsedPublicKeyModel: ParsedPublicKeyModel

        public var chainCode: ChainCode { try! ChainCode(rawRepresentation: payload.chainCode) }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Fingerprint { try! Fingerprint(rawRepresentation: payload.parentFingerprint) }
        public var childIndex: UInt32 { payload.childIndex }
        public var publicKey: OpalCrypto.Secp256k1.PublicKey {
            OpalCrypto.Secp256k1.PublicKey(parsedPublicKeyModel: parsedPublicKeyModel)
        }

        public init(_ serialized: String) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("extended_public_parse"),
                OpalCryptoDiagnostics.formatField("bip32_xpub"),
                OpalCryptoDiagnostics.publicField("input_character_count", serialized.count)
            ]
            do {
                let payload = try Self.makePayload(from: serialized)
                try self.init(payload: payload)
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.extendedPublicParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.extendedPublicParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields
            )
        }

        public func serialize() -> String {
            payload.serialize()
        }

        public func derived(indices: [UInt32]) throws -> ExtendedPublic {
            var currentPayload = payload
            var currentParsedPublicKeyModel = parsedPublicKeyModel
            for index in indices {
                do {
                    let childMaterial = try ExtendedKeyDerivationModel
                        .derivePublicChildMaterial(
                        from: currentPayload,
                        parsedPublicKeyModel: currentParsedPublicKeyModel,
                        index: index
                    )
                    currentPayload = childMaterial.payload
                    currentParsedPublicKeyModel = childMaterial.parsedPublicKeyModel
                } catch let error as ExtendedKeyDerivationModel.Error {
                    throw Self.mapDerivationError(error)
                }
            }
            return ExtendedPublic(
                payload: currentPayload,
                parsedPublicKeyModel: currentParsedPublicKeyModel
            )
        }

        internal init(payload: ExtendedKeyPayloadModel) throws {
            guard payload.kind == .publicKey else {
                throw Error.invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion)
            }
            self.payload = payload
            do {
                self.parsedPublicKeyModel = try ParsedPublicKeyModel(
                    publicKeyData: payload.keyData
                )
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(expected: 33, actual: actual)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }
        }

        internal init(
            payload: ExtendedKeyPayloadModel,
            parsedPublicKeyModel: ParsedPublicKeyModel
        ) {
            self.payload = payload
            self.parsedPublicKeyModel = parsedPublicKeyModel
        }

        internal init(
            depth: UInt8,
            parentFingerprintUInt32BigEndian: UInt32,
            childIndex: UInt32,
            chainCode: Data,
            parsedPublicKeyModel: ParsedPublicKeyModel
        ) {
            self.payload = ExtendedKeyPayloadModel.makeTrustedDerivedPublicKey(
                depth: depth,
                parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
                childIndex: childIndex,
                chainCode: chainCode,
                publicKeyData33Bytes: parsedPublicKeyModel.compressedPublicKeyData
            )
            self.parsedPublicKeyModel = parsedPublicKeyModel
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
                return .invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion)
            case .invalidPrivateKeyLength:
                return .invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion)
            case .invalidPrivateKey:
                return .invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion)
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            }
        }

        private static func mapDerivationError(_ error: ExtendedKeyDerivationModel.Error) -> Error {
            switch error {
            case .hardenedDerivationRequiresPrivateKey:
                return .hardenedDerivationRequiresPrivateKey
            case .depthOverflow:
                return .depthOverflow
            case .invalidSeed, .invalidKeyKind, .invalidDerivedKey:
                return .invalidDerivedKey
            }
        }
    }
}
