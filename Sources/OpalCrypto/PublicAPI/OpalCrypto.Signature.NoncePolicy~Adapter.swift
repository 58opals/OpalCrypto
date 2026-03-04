import Foundation

extension OpalCrypto.Signature.NoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .rfc6979:
            return .requestForComments6979BitcoinCashDefault
        case .bip340Deterministic:
            return .bitcoinImprovementProposalSchnorrDeterministic
        case .random:
            return .systemRandom
        }
    }
}
