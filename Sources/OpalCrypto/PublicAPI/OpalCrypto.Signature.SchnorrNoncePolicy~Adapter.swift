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

    var diagnosticsName: String {
        switch self {
        case .bip340Deterministic:
            return "bip340_deterministic"
        case .random:
            return "random"
        }
    }
}
