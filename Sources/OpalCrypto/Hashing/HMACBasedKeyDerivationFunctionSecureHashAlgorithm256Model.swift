// HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model.swift

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
        let pseudorandomKey =
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(inputKeyMaterial, key: resolvedSalt)
        let blockCount = (outputByteCount + hashByteCount - 1) / hashByteCount

        var output = Data()
        output.reserveCapacity(outputByteCount)
        var previousBlock = Data()
        for blockIndex in 1...blockCount {
            var blockInput = previousBlock
            blockInput.append(information)
            blockInput.append(UInt8(blockIndex))
            previousBlock =
                HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                    .hash(blockInput, key: pseudorandomKey)
            output.append(previousBlock)
        }
        return Data(output.prefix(outputByteCount))
    }
}
