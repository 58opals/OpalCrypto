// PasswordBasedKeyDerivationFunction2Model.swift

import Foundation
import CryptoKit

internal struct PasswordBasedKeyDerivationFunction2Model {

    private static let sha512BlockSize = 512 / 8
    static let defaultDerivedKeyLength = sha512BlockSize

    let symmetricKey: SymmetricKey
    let salt: Data
    let iterationCount: Int
    let blockCount: Int
    let derivedKeyLength: Int

    let sha512BlockSize = Self.sha512BlockSize

    internal init(
        password: Data,
        salt: Data,
        iterationCount: Int = 4096,
        derivedKeyLength: Int? = nil,
        maximumWorkUnitCount: UInt64
    ) throws {
        guard iterationCount > 0 else {
            throw Error.invalidIterationCount(actual: iterationCount)
        }
        guard !salt.isEmpty else {
            throw Error.emptySalt
        }

        let resolvedDerivedKeyLength = derivedKeyLength ?? Self.defaultDerivedKeyLength
        guard resolvedDerivedKeyLength > 0 else {
            throw Error.invalidDerivedKeyLength(actual: resolvedDerivedKeyLength)
        }

        let completeBlockCount = resolvedDerivedKeyLength / Self.sha512BlockSize
        let partialBlockCount = resolvedDerivedKeyLength % Self.sha512BlockSize == 0 ? 0 : 1
        let blockCount = completeBlockCount + partialBlockCount
        guard UInt64(blockCount) <= UInt64(UInt32.max) else {
            throw Error.keyLengthExceedsLimit(actual: resolvedDerivedKeyLength)
        }

        let (requiredWorkUnitCount, workUnitCountOverflowed) = UInt64(blockCount)
            .multipliedReportingOverflow(by: UInt64(iterationCount))
        guard !workUnitCountOverflowed else {
            throw Error.workUnitCountOverflow
        }
        guard requiredWorkUnitCount <= maximumWorkUnitCount else {
            throw Error.workBudgetExceeded(
                requiredWorkUnitCount: requiredWorkUnitCount,
                maximumWorkUnitCount: maximumWorkUnitCount
            )
        }

        self.symmetricKey = SymmetricKey(data: password)
        self.salt = salt
        self.iterationCount = iterationCount
        self.derivedKeyLength = resolvedDerivedKeyLength
        self.blockCount = blockCount
    }

    internal func deriveKey() throws -> Data {
        try Task.checkCancellation()
        var derivedKey = Data()
        derivedKey.reserveCapacity(self.derivedKeyLength)
        var remainingByteCount = derivedKeyLength
        for blockIndex in 1...self.blockCount {
            try Task.checkCancellation()
            let block = try computeBlock(blockNumber: blockIndex)
            if remainingByteCount >= block.count {
                derivedKey.append(contentsOf: block)
                remainingByteCount -= block.count
            } else {
                derivedKey.append(contentsOf: block.prefix(remainingByteCount))
                remainingByteCount = 0
                break
            }
        }
        return derivedKey
    }
}
