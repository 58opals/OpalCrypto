// NonceGenerationPolicy+EllipticCurveDigitalSignatureAlgorithmModel.swift

import Foundation

extension NonceGenerationPolicy {
    internal enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable, Equatable {
        case requestForComments6979SecureHashAlgorithm256
        case systemRandom
    }
}
