// OpalCrypto.Nostr.NIP44+Error.swift

extension OpalCrypto.Nostr.NIP44 {
    public enum Error: Swift.Error, Sendable, Equatable {
        case invalidConversationKeyLength(expected: Int, actual: Int)
        case invalidNonceLength(expected: Int, actual: Int)
        case randomGenerationFailed
        case emptyPlaintext
        case plaintextByteCountExceedsMaximum(maximum: Int, actual: Int)
        case plaintextByteCountExceedsStandardLimit(actual: Int)
        case invalidMaximumPlaintextByteCount(Int)
        case invalidEncodedPayloadByteCount(minimum: Int, maximum: Int, actual: Int)
        case unsupportedEncoding
        case invalidBase64
        case nonCanonicalBase64
        case unsupportedVersion(UInt8)
        case invalidPayload
        case authenticationFailed
        case invalidPadding
        case invalidUTF8
    }
}
