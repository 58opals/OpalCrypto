// PasswordBasedKeyDerivationFunction2Model+Error.swift

import Foundation
import CryptoKit

extension PasswordBasedKeyDerivationFunction2Model {
    internal enum Error: Swift.Error, Equatable {
        case invalidIterationCount(actual: Int)
        case emptySalt
        case invalidDerivedKeyLength(actual: Int)
        case keyLengthExceedsLimit(actual: Int)
        case workBudgetExceeded(
            requiredWorkUnitCount: UInt64,
            maximumWorkUnitCount: UInt64
        )
        case workUnitCountOverflow
    }
}
