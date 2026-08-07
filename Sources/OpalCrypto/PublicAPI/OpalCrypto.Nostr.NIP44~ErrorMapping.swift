// OpalCrypto.Nostr.NIP44~ErrorMapping.swift

extension OpalCrypto.Nostr.NIP44 {
    static func mapError(
        _ error: NostrImplementationPossibility44Model.Error
    ) -> Error {
        switch error {
        case .emptyPlaintext:
            .emptyPlaintext
        case let .plaintextByteCountExceedsMaximum(maximum, actual):
            .plaintextByteCountExceedsMaximum(
                maximum: maximum,
                actual: actual
            )
        case let .plaintextByteCountExceedsStandardLimit(actual):
            .plaintextByteCountExceedsStandardLimit(actual: actual)
        case let .invalidMaximumPlaintextByteCount(maximum):
            .invalidMaximumPlaintextByteCount(maximum)
        case let .invalidEncodedPayloadByteCount(minimum, maximum, actual):
            .invalidEncodedPayloadByteCount(
                minimum: minimum,
                maximum: maximum,
                actual: actual
            )
        case .unsupportedEncoding:
            .unsupportedEncoding
        case .invalidBase64:
            .invalidBase64
        case .nonCanonicalBase64:
            .nonCanonicalBase64
        case let .unsupportedVersion(version):
            .unsupportedVersion(version)
        case .invalidPayload:
            .invalidPayload
        case .authenticationFailed:
            .authenticationFailed
        case .invalidPadding:
            .invalidPadding
        case .invalidUTF8:
            .invalidUTF8
        }
    }
}
