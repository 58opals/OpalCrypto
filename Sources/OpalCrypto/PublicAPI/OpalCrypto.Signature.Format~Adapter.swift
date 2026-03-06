// OpalCrypto.Signature.Format~Adapter.swift

import Foundation

extension OpalCrypto.Signature.Format {
    var internalFormat: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormat {
        switch self {
        case .ecdsa(let encoding):
            switch encoding {
            case .raw:
                return .ecdsa(.raw)
            case .der:
                return .ecdsa(.distinguishedEncodingRules)
            }
        case .schnorr:
            return .schnorr
        }
    }
}
