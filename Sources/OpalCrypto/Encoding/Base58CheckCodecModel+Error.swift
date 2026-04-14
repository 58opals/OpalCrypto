// Base58CheckCodecModel+Error.swift

import Foundation

extension Base58CheckCodecModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidPayloadLength(actual: Int)
        case invalidChecksum
    }
}
