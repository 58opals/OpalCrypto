// HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model.swift

import CryptoKit
import Foundation

internal enum HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model {
    static let hashByteCount = 32
    static let maximumDerivedKeyByteCount = 255 * hashByteCount

    static func deriveKey(
        inputKeyMaterial: Data,
        salt: Data,
        information: Data,
        outputByteCount: Int
    ) throws -> Data {
        guard outputByteCount > 0 else {
            throw Error.invalidDerivedKeyLength(actual: outputByteCount)
        }
        guard outputByteCount <= maximumDerivedKeyByteCount else {
            throw Error.derivedKeyLengthExceedsLimit(actual: outputByteCount)
        }

        let resolvedSalt = salt.isEmpty
            ? Data(repeating: 0, count: hashByteCount)
            : salt
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: resolvedSalt,
            info: information,
            outputByteCount: outputByteCount
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }
}
