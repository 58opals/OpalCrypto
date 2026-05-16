// Base58CheckCodec+Error.swift

import Foundation

extension Base58CheckCodec {
    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidPayloadLength(actual: Int)
        case invalidChecksum
    }
}
