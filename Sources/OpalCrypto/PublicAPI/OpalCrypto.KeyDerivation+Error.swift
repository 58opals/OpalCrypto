// OpalCrypto.KeyDerivation+Error.swift

import Foundation

extension OpalCrypto.KeyDerivation {
    public enum Error: Swift.Error, Equatable {
        case invalidIterationCount(actual: Int)
        case emptySalt
        case invalidDerivedKeyLength(actual: Int)
        case derivedKeyLengthExceedsLimit(actual: Int)
        case workBudgetExceeded(
            requiredWorkUnitCount: UInt64,
            maximumWorkUnitCount: UInt64
        )
        case workUnitCountOverflow
    }
}
