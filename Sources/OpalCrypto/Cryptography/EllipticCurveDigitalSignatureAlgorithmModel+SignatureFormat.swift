// EllipticCurveDigitalSignatureAlgorithmModel+SignatureFormat.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal enum SignatureFormat: Sendable {
        case ecdsa(EllipticCurveDigitalSignatureAlgorithm)
        case schnorr

    }
}
