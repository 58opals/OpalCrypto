// OpalCrypto.Pedersen+Error.swift

import Foundation

extension OpalCrypto.Pedersen {
    public enum Error: Swift.Error, Equatable {
        case invalidAlternateBasePointLength(actual: Int)
        case invalidAlternateBasePointPrefix(actual: UInt8)
        case invalidAlternateBasePoint
        case insecureAlternateBasePoint
        case invalidNonceLength(expected: Int, actual: Int)
        case invalidNonce
        case invalidCommitmentLength(actual: Int)
        case invalidCommitment
        case emptyCommitmentList
        case mismatchedSetup
        case cryptographyFailure
    }
}
