// HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model+Error.swift

extension HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model {
    internal enum Error: Swift.Error, Equatable {
        case invalidDerivedKeyLength(actual: Int)
        case derivedKeyLengthExceedsLimit(actual: Int)
    }
}
