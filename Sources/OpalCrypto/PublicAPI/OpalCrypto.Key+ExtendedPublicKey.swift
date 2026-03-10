// OpalCrypto.Key+ExtendedPublicKey.swift

import Foundation

extension OpalCrypto.Key {
    public struct ExtendedPublicKey: Sendable, Equatable {
        public enum Error: Swift.Error, Equatable {
            case invalidBase58
            case invalidChecksum
            case invalidVersion(actual: UInt32)
            case invalidPayloadLength(expected: Int, actual: Int)
            case invalidParentFingerprintLength(expected: Int, actual: Int)
            case invalidChainCodeLength(expected: Int, actual: Int)
            case invalidPublicKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidPublicKey
            case invalidDepthMetadata
            case hardenedDerivationRequiresPrivateKey
            case depthOverflow
            case invalidDerivedKey
        }

        internal let payload: ExtendedKeyPayloadModel

        public var chainCode: Data { payload.chainCode }
        public var depth: UInt8 { payload.depth }
        public var parentFingerprint: Data { payload.parentFingerprint }
        public var childIndex: UInt32 { payload.childIndex }
        public var publicKey: Data { payload.keyData }

        public init(_ serialized: String) throws {
            let payload = try Self.makePayload(from: serialized)
            guard payload.kind == .publicKey else {
                throw Error.invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion)
            }
            self.init(payload: payload)
        }

        public func serialize() -> String {
            payload.serialize()
        }

        public func derived(indices: [UInt32]) throws -> ExtendedPublicKey {
            var currentPayload = payload
            for index in indices {
                do {
                    currentPayload = try ExtendedKeyDerivationModel.derivePublicChild(
                        from: currentPayload,
                        index: index
                    )
                } catch let error as ExtendedKeyDerivationModel.Error {
                    throw Self.mapDerivationError(error)
                }
            }
            return ExtendedPublicKey(payload: currentPayload)
        }

        internal init(payload: ExtendedKeyPayloadModel) {
            self.payload = payload
        }

        internal init(
            depth: UInt8,
            parentFingerprint: Data,
            childIndex: UInt32,
            chainCode: Data,
            publicKey: Data
        ) {
            self.payload = try! ExtendedKeyPayloadModel(
                kind: .publicKey,
                depth: depth,
                parentFingerprint: parentFingerprint,
                childIndex: childIndex,
                chainCode: chainCode,
                keyData: publicKey
            )
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
