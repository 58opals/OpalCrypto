// OpalCrypto.Signature+Error.swift

import Foundation

extension OpalCrypto.Signature {
    public enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(expected: Int, actual: Int)
        case invalidPublicKeyLength(expected: Int, actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidSignatureLength(expected: Int, actual: Int)
        case cryptographyFailure
    }
}
