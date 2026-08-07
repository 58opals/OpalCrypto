// NostrImplementationPossibility44Model+Error.swift

extension NostrImplementationPossibility44Model {
    enum Error: Swift.Error, Sendable, Equatable {
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
