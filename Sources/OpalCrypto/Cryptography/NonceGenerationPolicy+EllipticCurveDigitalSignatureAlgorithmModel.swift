// NonceGenerationPolicy.swift

import Foundation

public enum NonceGenerationPolicy: Sendable, Equatable {
    case rfc6979BchDefault
    case bipSchnorrDeterministic
    case systemRandom
}

extension NonceGenerationPolicy {
    public enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable, Equatable {
        case rfc6979Sha256
        case systemRandom
    }
}
