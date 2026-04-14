// OpalCrypto.Key.WIF+Error.swift

import Foundation

extension OpalCrypto.Key.WIF {
    public enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidChecksum
        case invalidPayloadLength(actual: Int)
        case invalidVersion(actual: UInt8)
        case invalidCompressionMarker(actual: UInt8)
        case invalidPrivateKeyLength(expected: Int, actual: Int)
        case invalidPrivateKey
    }
}
