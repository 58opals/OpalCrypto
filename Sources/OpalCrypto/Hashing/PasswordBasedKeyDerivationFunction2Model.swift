// PasswordBasedKeyDerivationFunction2Model.swift

import Foundation
import CryptoKit

internal struct PasswordBasedKeyDerivationFunction2Model {

    private static let sha512BlockSize = 512 / 8
    private static let maximumDerivedKeyLength = Int(UInt64(UInt32.max) * UInt64(sha512BlockSize))
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
        derivedKeyLength: Int? = nil
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
        guard resolvedDerivedKeyLength <= Self.maximumDerivedKeyLength else {
            throw Error.keyLengthExceedsLimit(actual: resolvedDerivedKeyLength)
        }

        self.symmetricKey = SymmetricKey(data: password)
        self.salt = salt
        self.iterationCount = iterationCount
        self.derivedKeyLength = resolvedDerivedKeyLength
        self.blockCount = (resolvedDerivedKeyLength + Self.sha512BlockSize - 1) / Self.sha512BlockSize
    }

    internal func deriveKey() throws -> Data {
        var derivedKey = Data()
        derivedKey.reserveCapacity(self.derivedKeyLength)
        var remainingByteCount = derivedKeyLength
        for blockIndex in 1...self.blockCount {
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
