// CommunicationBoxModel+Error.swift

import Foundation

extension CommunicationBoxModel {
    enum Error: Swift.Error, Equatable {
        case invalidMessageLength(actual: Int)
        case messageTooLong(actual: Int)
        case invalidPublicKeyLength(expected: Int, actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
        case invalidSymmetricKeyLength(actual: Int)
        case invalidPaddedPlaintextLength(minimum: Int, actual: Int)
        case paddedPlaintextLengthNotMultipleOf16(actual: Int)
        case invalidCiphertext
        case cryptographyFailure
    }
}
