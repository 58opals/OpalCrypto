// OpalCrypto.Numeric+Error.swift

import Foundation

extension OpalCrypto.Numeric {
    public enum Error: Swift.Error, Equatable {
        case invalidDataLength(expected: Int, actual: Int)
        case invalidDivisor(actual: UInt64)
    }
}
