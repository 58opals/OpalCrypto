// EllipticCurveDigitalSignatureAlgorithmModel+Error.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    public enum Error: Swift.Error {
        case invalidCompressedPublicKeyLength
        case invalidCompressedPublicKeyPrefix
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidHashIterationCount
    }
}
