// OpalCrypto.Key+ChildDerivationError.swift

extension OpalCrypto.Key {
    /// Errors from focused key-and-chain-code child derivation.
    public enum ChildDerivationError: Swift.Error, Sendable, Equatable {
        /// The focused operation accepts only BIP-32 non-hardened indices.
        case hardenedIndex(UInt32)
        /// BIP-32 produced invalid child key material.
        case invalidDerivedKey
    }
}
