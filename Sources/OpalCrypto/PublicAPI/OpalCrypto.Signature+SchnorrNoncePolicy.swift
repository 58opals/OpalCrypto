// OpalCrypto.Signature+SchnorrNoncePolicy.swift

import Foundation

extension OpalCrypto.Signature {
    public enum SchnorrNoncePolicy: Sendable, Equatable {
        case bip340Deterministic
        case random
    }
}
