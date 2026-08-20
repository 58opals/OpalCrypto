// OpalCrypto.RSABSSA+Error.swift

extension OpalCrypto.RSABSSA {
    /// Validation and operation failures for the bounded RSABSSA profile.
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidMessageRandomizerLength(expected: Int, actual: Int)
        case invalidBlindRequestRecoveryStateLength(expected: Int, actual: Int)
        case unsupportedBlindRequestRecoveryStateVersion(UInt8)
        case blindRequestMessageMismatch
        case invalidBlindedMessageLength(expected: Int, actual: Int)
        case invalidBlindSignatureLength(expected: Int, actual: Int)
        case invalidSignatureLength(expected: Int, actual: Int)
        case invalidSubjectPublicKeyInfo
        case invalidModulusBitCount(expected: Int, actual: Int)
        case invalidPublicExponent(expected: Int, actual: Int)
        case keyGenerationFailed
        case randomGenerationFailed
        case invalidMessageRepresentative
        case blindingFailed
        case verificationKeyMismatch
        case messageRepresentativeOutOfRange
        case unsupportedKeyOperation
        case signingFailed
        case invalidBlindSignature
    }
}
