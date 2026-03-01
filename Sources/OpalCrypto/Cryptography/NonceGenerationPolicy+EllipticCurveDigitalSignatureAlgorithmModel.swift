// NonceGenerationPolicy+EllipticCurveDigitalSignatureAlgorithmModel.swift

import Foundation

extension NonceGenerationPolicy {
    public enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable, Equatable {
        case requestForComments6979SecureHashAlgorithm256
        case systemRandom
    }
}
