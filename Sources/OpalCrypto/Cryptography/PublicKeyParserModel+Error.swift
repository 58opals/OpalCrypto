// PublicKeyParserModel+Error.swift

import Foundation

extension PublicKeyParserModel {
    enum Error: Swift.Error, Equatable {
        case invalidLength(actual: Int)
        case invalidPrefix(byte: UInt8)
        case invalidPoint
    }
}
