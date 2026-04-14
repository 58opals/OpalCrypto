// OpalCrypto.Secp256k1+Error.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(expected: Int, actual: Int)
        case invalidPrivateKey
        case invalidPublicKeyLength(expected: Int, actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidTweakLength(expected: Int, actual: Int)
        case invalidTweak
        case invalidDerivedKey
        case invalidSignatureLength(expected: Int, actual: Int)
        case invalidSignature
        case invalidDER
        case nonCanonicalDER
        case randomGenerationFailed(status: Int32)
    }
}
