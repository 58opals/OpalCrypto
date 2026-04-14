// OpalCrypto.Encoding+Error.swift

import Foundation

extension OpalCrypto.Encoding {
    public enum Error: Swift.Error, Equatable {
        case invalidFiveBitValue(actual: UInt8)
        case invalidCharacterFound
    }
}
