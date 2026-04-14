// ExtendedKeyDerivationModel+Error.swift

import Foundation

extension ExtendedKeyDerivationModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidSeed
        case invalidKeyKind
        case hardenedDerivationRequiresPrivateKey
        case depthOverflow
        case invalidDerivedKey
    }
}
