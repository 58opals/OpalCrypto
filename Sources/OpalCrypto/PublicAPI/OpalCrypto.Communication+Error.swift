// OpalCrypto.Communication+Error.swift

import Foundation

extension OpalCrypto.Communication {
    public enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(expected: Int, actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidPrivateKeyLength(expected: Int, actual: Int)
        case invalidPrivateKey
        case invalidSymmetricKeyLength(expected: Int, actual: Int)
        case invalidPaddedPlaintextLength(minimum: Int, actual: Int)
        case paddedPlaintextLengthMustBeMultipleOf16(actual: Int)
        case invalidCiphertext
        case cryptographyFailure
    }
}
