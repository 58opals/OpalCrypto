// OpalCrypto.Key+ExtendedPrivateKey.swift

import Foundation

extension OpalCrypto.Key {
    public struct ExtendedPrivateKey: Sendable, Equatable {
        public enum Error: Swift.Error, Equatable {
            case invalidBase58
            case invalidChecksum
            case invalidVersion(actual: UInt32)
            case invalidPayloadLength(expected: Int, actual: Int)
            case invalidParentFingerprintLength(expected: Int, actual: Int)
            case invalidChainCodeLength(expected: Int, actual: Int)
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPrivateKey
            case invalidDepthMetadata
            case depthOverflow
            case invalidDerivedKey
        }

        internal let payload: ExtendedKeyPayloadModel
        internal let compressedPublicKeyData: Data
        internal let compressedPublicKeyFingerprintData4Bytes: Data

        public var chainCode: Data { payload.chainCode }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Data { payload.parentFingerprint }
        public var childIndex: UInt32 { payload.childIndex }
        public var privateKey: Data { payload.keyData }

        public var publicKey: ExtendedPublicKey {
            ExtendedPublicKey(
                depth: payload.depth,
                parentFingerprint: payload.parentFingerprint,
                childIndex: payload.childIndex,
                chainCode: payload.chainCode,
                publicKey: compressedPublicKeyData
            )
        }

        public init(_ serialized: String) throws {
            let payload = try Self.makePayload(from: serialized)
            try self.init(payload: payload)
        }

        public static func root(seed: Data) throws -> ExtendedPrivateKey {
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
            return try ExtendedPrivateKey(payload: payload)
        }

        public func serialize() -> String {
            payload.serialize()
        }

        public func derived(indices: [UInt32]) throws -> ExtendedPrivateKey {
            var currentPayload = payload
            var currentCompressedPublicKeyData = compressedPublicKeyData
            var currentCompressedPublicKeyFingerprintData4Bytes =
                compressedPublicKeyFingerprintData4Bytes
            for index in indices {
                do {
                    let childMaterial = try ExtendedKeyDerivationModel
                        .derivePrivateChildMaterial(
                        from: currentPayload,
                        parentCompressedPublicKeyData: currentCompressedPublicKeyData,
                        parentCompressedPublicKeyFingerprintData4Bytes:
                            currentCompressedPublicKeyFingerprintData4Bytes,
                        index: index
                    )
                    currentPayload = childMaterial.payload
                    currentCompressedPublicKeyData = childMaterial.compressedPublicKeyData
                    currentCompressedPublicKeyFingerprintData4Bytes =
                        childMaterial.compressedPublicKeyFingerprintData4Bytes
                } catch let error as ExtendedKeyDerivationModel.Error {
                    throw Self.mapDerivationError(error)
                }
            }
            return ExtendedPrivateKey(
                payload: currentPayload,
                compressedPublicKeyData: currentCompressedPublicKeyData,
                compressedPublicKeyFingerprintData4Bytes:
                    currentCompressedPublicKeyFingerprintData4Bytes
            )
        }

        internal init(payload: ExtendedKeyPayloadModel) throws {
            guard payload.kind == .privateKey else {
                throw Error.invalidVersion(actual: ExtendedKeyPayloadModel.publicVersion)
            }
            let publicPayload = try ExtendedKeyDerivationModel.makePublicKey(from: payload)
            self.payload = payload
            self.compressedPublicKeyData = publicPayload.keyData
            self.compressedPublicKeyFingerprintData4Bytes = Data(
                SecureHash160Model.hash(publicPayload.keyData).prefix(4)
            )
        }

        internal init(
            payload: ExtendedKeyPayloadModel,
            compressedPublicKeyData: Data,
            compressedPublicKeyFingerprintData4Bytes: Data
        ) {
            self.payload = payload
            self.compressedPublicKeyData = compressedPublicKeyData
            self.compressedPublicKeyFingerprintData4Bytes = compressedPublicKeyFingerprintData4Bytes
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
