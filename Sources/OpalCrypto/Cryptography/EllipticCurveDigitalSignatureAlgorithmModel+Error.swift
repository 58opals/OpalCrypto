// EllipticCurveDigitalSignatureAlgorithmModel+Error.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal enum Error: Swift.Error {
        case invalidCompressedPublicKeyLength
        case invalidCompressedPublicKeyPrefix
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidHashIterationCount
    }
}
