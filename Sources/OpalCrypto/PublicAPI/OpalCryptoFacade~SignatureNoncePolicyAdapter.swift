import Foundation

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
