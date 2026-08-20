// OpalCrypto.AuthenticatedEncryption.AES256GCM+Error.swift

extension OpalCrypto.AuthenticatedEncryption.AES256GCM {
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidKeyLength(expected: Int, actual: Int)
        case invalidNonceLength(expected: Int, actual: Int)
        case randomGenerationFailed
        case invalidMaximumCombinedByteCount(minimum: Int, actual: Int)
        case combinedByteCountExceedsMaximum(maximum: Int, actual: Int)
        case malformedSealedBox
        case sealingFailed
        case authenticationFailed
    }
}
