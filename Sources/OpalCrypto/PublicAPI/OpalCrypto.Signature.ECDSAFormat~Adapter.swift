// OpalCrypto.Signature.ECDSAFormat~Adapter.swift

import Foundation

extension OpalCrypto.Signature.ECDSAFormat {
    var internalFormat: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormat {
        switch self {
        case .raw:
            return .ecdsa(.raw)
        case .der:
            return .ecdsa(.distinguishedEncodingRules)
        }
    }
}
