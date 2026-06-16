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

    var internalECDSANoncePolicy: NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel {
        switch self {
        case .rfc6979:
            return .requestForComments6979SecureHashAlgorithm256
        case .random:
            return .systemRandom
        }
    }

    var diagnosticsName: String {
        switch self {
        case .rfc6979:
            return "rfc6979"
        case .random:
            return "random"
        }
    }
}
