// OpalCrypto.Signature.SchnorrNoncePolicy~Adapter.swift

import Foundation

extension OpalCrypto.Signature.SchnorrNoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .bchDeterministic:
            return .requestForComments6979BitcoinCashDefault
        case .bip340Deterministic:
            return .bitcoinImprovementProposalSchnorrDeterministic
        case .random:
            return .systemRandom
        }
    }

    var diagnosticsName: String {
        switch self {
        case .bchDeterministic:
            return "bch_deterministic"
        case .bip340Deterministic:
            return "legacy_bip_schnorr_deterministic"
        case .random:
            return "random"
        }
    }
}
