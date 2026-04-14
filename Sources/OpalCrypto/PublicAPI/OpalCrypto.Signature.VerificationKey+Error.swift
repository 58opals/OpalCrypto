// OpalCrypto.Signature.VerificationKey+Error.swift

import Foundation

extension OpalCrypto.Signature.VerificationKey {
    public enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }
}
