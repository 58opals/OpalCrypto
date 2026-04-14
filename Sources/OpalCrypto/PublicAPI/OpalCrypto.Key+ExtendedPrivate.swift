// OpalCrypto.Key+ExtendedPrivate.swift

import Foundation

extension OpalCrypto.Key {
    public struct ExtendedPrivate: Sendable, Equatable {

        internal let payload: ExtendedKeyPayloadModel
        internal let parsedPrivateKeyModel: ParsedPrivateKeyModel

        public var chainCode: Data { payload.chainCode }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Data { payload.parentFingerprint }
        public var childIndex: UInt32 { payload.childIndex }
        public var privateKey: Data { payload.keyData }

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
            let payload = try Self.makePayload(from: serialized)
            try self.init(payload: payload)
        }

        public static func root(seed: Data) throws -> ExtendedPrivate {
            let payload: ExtendedKeyPayloadModel
            do {
                payload = try ExtendedKeyDerivationModel.makeRootPrivateKey(seed: seed)
            } catch let error as ExtendedKeyDerivationModel.Error {
                switch error {
                case .invalidSeed:
                    throw Error.invalidDerivedKey
                case .invalidKeyKind,
                     .hardenedDerivationRequiresPrivateKey,
                     .depthOverflow,
                     .invalidDerivedKey:
                    throw Error.invalidDerivedKey
                }
            }
            return try ExtendedPrivate(payload: payload)
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
            case .invalidParentFingerprintLength(let actual):
                return .invalidParentFingerprintLength(expected: 4, actual: actual)
            case .invalidChainCodeLength(let actual):
                return .invalidChainCodeLength(expected: 32, actual: actual)
            case .invalidDepthMetadata:
                return .invalidDepthMetadata
            case .invalidPrivateKeyPrefix,
                 .invalidPublicKeyLength,
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
