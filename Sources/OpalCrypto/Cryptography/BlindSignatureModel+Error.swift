// BlindSignatureModel+Error.swift

import Foundation

extension BlindSignatureModel {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidNoncePointLength(actual: Int)
        case invalidNoncePointPrefix(actual: UInt8)
        case invalidNoncePoint
        case invalidDigestLength(actual: Int)
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
        case invalidRequestLength(actual: Int)
        case invalidRequestScalar
        case invalidResponseLength(actual: Int)
        case invalidResponseScalar
        case randomGenerationFailed
        case nonceAlreadyUsed
        case verificationFailed
        case cryptographyFailure
    }
}
