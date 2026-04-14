// VerificationKeyModel+Error.swift

import Foundation

extension VerificationKeyModel {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }
}
