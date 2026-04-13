// OpalCrypto.Signature.SchnorrNoncePolicy~Adapter.swift

import Foundation

extension OpalCrypto.Signature.SchnorrNoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .bip340Deterministic:
            return .bitcoinImprovementProposalSchnorrDeterministic
        case .random:
            return .systemRandom
        }
    }
}
