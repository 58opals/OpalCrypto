// EllipticCurveDigitalSignatureAlgorithmModel+SignatureFormat.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal enum SignatureFormat: Sendable {
        case ecdsa(EllipticCurveDigitalSignatureAlgorithm)
        case schnorr

        internal enum EllipticCurveDigitalSignatureAlgorithm: Sendable {
            case raw
            case compact
            case distinguishedEncodingRules
        }
    }
}
