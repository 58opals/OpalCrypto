// OpalCrypto.RSABSSA+Error.swift

extension OpalCrypto.RSABSSA {
    /// Structural validation failures for RSABSSA data.
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidMessageRandomizerLength(expected: Int, actual: Int)
        case invalidBlindedMessageLength(expected: Int, actual: Int)
        case invalidBlindSignatureLength(expected: Int, actual: Int)
        case invalidSignatureLength(expected: Int, actual: Int)
    }
}
