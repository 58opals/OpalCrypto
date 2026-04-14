// OpalCrypto.Signature+ECDSANoncePolicy.swift

import Foundation

extension OpalCrypto.Signature {
    public enum ECDSANoncePolicy: Sendable, Equatable {
        case rfc6979
        case random
    }
}
