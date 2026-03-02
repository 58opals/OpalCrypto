// EllipticCurveDigitalSignatureAlgorithmModel+SignatureFormatModel.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal enum SignatureFormatModel: Sendable {
        case ecdsa(EllipticCurveDigitalSignatureAlgorithmModel)
        case schnorr

        internal enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable {
            case raw
            case compact
            case distinguishedEncodingRules
        }
    }
}
