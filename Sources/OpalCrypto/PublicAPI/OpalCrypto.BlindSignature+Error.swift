// OpalCrypto.BlindSignature+Error.swift

import Foundation

extension OpalCrypto.BlindSignature {
    public enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidNoncePointLength(actual: Int)
        case invalidNoncePointPrefix(actual: UInt8)
        case invalidNoncePoint
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidPrivateKeyLength(expected: Int, actual: Int)
        case invalidPrivateKey
        case invalidRequestLength(expected: Int, actual: Int)
        case invalidResponseLength(expected: Int, actual: Int)
        case nonceAlreadyUsed
        case cryptographyFailure
        case verificationFailed
    }
}
