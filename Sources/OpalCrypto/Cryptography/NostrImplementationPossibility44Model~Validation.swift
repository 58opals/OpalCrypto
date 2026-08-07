// NostrImplementationPossibility44Model~Validation.swift

import Foundation

extension NostrImplementationPossibility44Model {
    static func validatePlaintextByteCount(
        _ actual: Int,
        maximumPlaintextByteCount: Int
    ) throws {
        try validateMaximumPlaintextByteCount(maximumPlaintextByteCount)
        guard actual > 0 else {
            throw Error.emptyPlaintext
        }
        guard actual <= standardMaximumPlaintextByteCount else {
            throw Error.plaintextByteCountExceedsStandardLimit(actual: actual)
        }
        guard actual <= maximumPlaintextByteCount else {
            throw Error.plaintextByteCountExceedsMaximum(
                maximum: maximumPlaintextByteCount,
                actual: actual
            )
        }
    }

    static func validateMaximumPlaintextByteCount(_ maximum: Int) throws {
        guard maximum > 0,
              maximum <= standardMaximumPlaintextByteCount else {
            throw Error.invalidMaximumPlaintextByteCount(maximum)
        }
    }

    static func parsePayload(
        _ encodedPayload: String,
        maximumEncodedPayloadByteCount: Int
    ) throws -> ParsedPayload {
        guard encodedPayload.first != "#" else {
            throw Error.unsupportedEncoding
        }
        let encodedByteCount = encodedPayload.utf8.count
        guard maximumEncodedPayloadByteCount >= minimumEncodedPayloadByteCount,
              encodedByteCount >= minimumEncodedPayloadByteCount,
              encodedByteCount <= maximumEncodedPayloadByteCount else {
            throw Error.invalidEncodedPayloadByteCount(
                minimum: minimumEncodedPayloadByteCount,
                maximum: maximumEncodedPayloadByteCount,
                actual: encodedByteCount
            )
        }
        guard let decoded = Data(base64Encoded: encodedPayload) else {
            throw Error.invalidBase64
        }
        guard decoded.base64EncodedString() == encodedPayload else {
            throw Error.nonCanonicalBase64
        }
        guard decoded.count >= minimumDecodedPayloadByteCount else {
            throw Error.invalidPayload
        }
        guard decoded[decoded.startIndex] == version else {
            throw Error.unsupportedVersion(decoded[decoded.startIndex])
        }
        let nonceStart = decoded.startIndex + 1
        let ciphertextStart = nonceStart + nonceByteCount
        let authenticationStart = decoded.endIndex - authenticationCodeByteCount
        guard ciphertextStart < authenticationStart else {
            throw Error.invalidPayload
        }
        return ParsedPayload(
            nonce: Data(decoded[nonceStart ..< ciphertextStart]),
            ciphertext: Data(decoded[ciphertextStart ..< authenticationStart]),
            authenticationCode: Data(decoded[authenticationStart ..< decoded.endIndex])
        )
    }
}
