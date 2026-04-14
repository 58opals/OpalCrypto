// EllipticCurveDigitalSignatureAlgorithmModel+Error.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal enum Error: Swift.Error {
        case invalidCompressedPublicKeyLength(expected: Int, actual: Int)
        case invalidCompressedPublicKeyPrefix(actual: UInt8)
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidHashIterationCount
    }
}
