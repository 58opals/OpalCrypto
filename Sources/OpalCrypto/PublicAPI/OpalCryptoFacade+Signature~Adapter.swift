import Foundation

extension OpalCryptoFacade.Signature.Format {
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

extension OpalCryptoFacade.Signature.NoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .requestForComments6979:
            return .requestForComments6979BitcoinCashDefault
        case .bitcoinImprovementProposalSchnorrDeterministic:
            return .bitcoinImprovementProposalSchnorrDeterministic
        case .systemRandom:
            return .systemRandom
        }
    }
}
