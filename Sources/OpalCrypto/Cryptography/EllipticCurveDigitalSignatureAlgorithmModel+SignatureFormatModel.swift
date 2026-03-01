// EllipticCurveDigitalSignatureAlgorithmModel+SignatureFormatModel.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    public enum SignatureFormatModel: Sendable {
        case ecdsa(EllipticCurveDigitalSignatureAlgorithmModel)
        case schnorr

        public enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable {
            case raw
            case compact
            case distinguishedEncodingRules
        }
    }
}
