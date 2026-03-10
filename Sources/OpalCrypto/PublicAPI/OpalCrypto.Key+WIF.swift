// OpalCrypto.Key+WIF.swift

import Foundation

extension OpalCrypto.Key {
    public struct WIF: Sendable, Equatable {
        public enum Error: Swift.Error, Equatable {
            case invalidBase58
            case invalidChecksum
            case invalidPayloadLength(actual: Int)
            case invalidVersion(actual: UInt8)
            case invalidCompressionMarker(actual: UInt8)
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPrivateKey
        }

        public let privateKey: Data
        public let isCompressed: Bool

        public init(privateKey: Data, isCompressed: Bool = true) throws {
            guard privateKey.count == 32 else {
                throw Error.invalidPrivateKeyLength(expected: 32, actual: privateKey.count)
            }
            guard StandardsForEfficientCryptography256k1CurveModel.Operation
                .isPrivateKeyData32BytesValid(privateKey) else {
                throw Error.invalidPrivateKey
            }
            self.privateKey = privateKey
            self.isCompressed = isCompressed
        }

        public init(_ serialized: String) throws {
            do {
                let decoded = try WalletImportFormatCodecModel.decode(serialized)
                self.privateKey = decoded.privateKey
                self.isCompressed = decoded.isCompressed
            } catch let error as WalletImportFormatCodecModel.Error {
                throw Self.mapError(error)
            }
        }

        public func serialize() throws -> String {
            do {
                return try WalletImportFormatCodecModel.encode(
                    privateKey: privateKey,
                    isCompressed: isCompressed
                )
            } catch let error as WalletImportFormatCodecModel.Error {
                throw Self.mapError(error)
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
    }
}
