// OpalCrypto.Signature.ECDSANoncePolicy~Adapter.swift

import Foundation

extension OpalCrypto.Signature.ECDSANoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .rfc6979:
            return .requestForComments6979BitcoinCashDefault
        case .random:
            return .systemRandom
        }
    }
}
