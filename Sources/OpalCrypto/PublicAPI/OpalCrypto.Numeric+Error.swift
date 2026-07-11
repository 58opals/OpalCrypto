// OpalCrypto.Numeric+Error.swift

import Foundation

extension OpalCrypto.Numeric {
    /// An error reported by a numeric facade operation.
    public enum Error: Swift.Error, Equatable {
        /// A fixed-width numeric value received the wrong number of bytes.
        case invalidDataLength(expected: Int, actual: Int)
        /// An integer division operation received zero as its divisor.
        case invalidDivisor(actual: UInt64)
    }
}
