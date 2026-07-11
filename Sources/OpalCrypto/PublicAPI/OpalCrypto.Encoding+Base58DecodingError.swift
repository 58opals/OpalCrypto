// OpalCrypto.Encoding+Base58DecodingError.swift

extension OpalCrypto.Encoding {
    /// An error reported by validating Base58 decoding.
    public enum Base58DecodingError: Swift.Error, Equatable {
        /// The input contains text outside the Base58 alphabet.
        case invalidText
    }
}
