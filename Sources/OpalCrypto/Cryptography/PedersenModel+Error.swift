// PedersenModel+Error.swift

import Foundation

extension PedersenModel {
    enum Error: Swift.Error, Equatable {
        case invalidAlternateBasePointLength(actual: Int)
        case invalidAlternateBasePointPrefix(actual: UInt8)
        case invalidAlternateBasePoint
        case insecureAlternateBasePoint
        case invalidNonceLength(actual: Int)
        case invalidNonce
        case invalidCommitmentLength(actual: Int)
        case invalidCommitment
        case emptyCommitmentList
        case mismatchedSetup
        case cryptographyFailure
    }
}
