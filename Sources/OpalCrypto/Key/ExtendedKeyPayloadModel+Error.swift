// ExtendedKeyPayloadModel+Error.swift

import Foundation

extension ExtendedKeyPayloadModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidChecksum
        case invalidVersion(actual: UInt32)
        case invalidPayloadLength(actual: Int)
        case payloadLengthExceedsMaximum(maximum: Int)
        case invalidChainCodeLength(actual: Int)
        case invalidDepthMetadata
        case invalidPrivateKeyPrefix(actual: UInt8)
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }
}
