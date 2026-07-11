// OpalCrypto.Secp256k1~OperationError.swift

extension OpalCrypto.Secp256k1 {
    static func mapOperationError(
        _ error: StandardsForEfficientCryptography256k1CurveModel.Operation.Error
    ) -> Error {
        switch error {
        case .invalidPrivateKeyLength(let actual):
            return .invalidPrivateKeyLength(expected: 32, actual: actual)
        case .invalidPrivateKeyValue:
            return .invalidPrivateKey
        case .invalidPublicKeyLength(let actual):
            return .invalidPublicKeyLength(expected: 33, actual: actual)
        case .invalidPublicKeyValue:
            return .invalidPublicKey
        case .invalidTweakLength(let actual):
            return .invalidTweakLength(expected: 32, actual: actual)
        case .invalidTweakValue:
            return .invalidTweak
        case .invalidDerivedPrivateKey, .invalidDerivedPublicKey:
            return .invalidDerivedKey
        case .randomGenerationFailed(let status):
            return .randomGenerationFailed(status: status)
        }
    }
}
