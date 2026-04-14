// ParsedPrivateKeyModel+Error.swift

import Foundation

extension ParsedPrivateKeyModel {
    enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
    }
}
