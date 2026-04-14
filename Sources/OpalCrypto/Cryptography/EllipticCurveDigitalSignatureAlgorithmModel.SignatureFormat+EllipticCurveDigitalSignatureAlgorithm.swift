// EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormat+EllipticCurveDigitalSignatureAlgorithm.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormat {
    internal enum EllipticCurveDigitalSignatureAlgorithm: Sendable {
        case raw
        case compact
        case distinguishedEncodingRules
    }
}
