// OpalCrypto.Key.ExtendedPrivate+Error.swift

import Foundation

extension OpalCrypto.Key.ExtendedPrivate {
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
}
