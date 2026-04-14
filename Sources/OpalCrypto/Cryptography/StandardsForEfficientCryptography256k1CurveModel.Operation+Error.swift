// StandardsForEfficientCryptography256k1CurveModel.Operation+Error.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    internal enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKeyValue
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyValue
        case invalidTweakLength(actual: Int)
        case invalidTweakValue
        case invalidDerivedPrivateKey
        case invalidDerivedPublicKey
        case randomGenerationFailed(status: Int32)
    }
}
