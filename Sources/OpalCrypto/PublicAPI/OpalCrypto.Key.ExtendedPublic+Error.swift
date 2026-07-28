// OpalCrypto.Key.ExtendedPublic+Error.swift

import Foundation

extension OpalCrypto.Key.ExtendedPublic {
    public enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidChecksum
        case invalidVersion(actual: UInt32)
        case invalidPayloadLength(expected: Int, actual: Int)
        case payloadLengthExceedsMaximum(maximum: Int)
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
}
