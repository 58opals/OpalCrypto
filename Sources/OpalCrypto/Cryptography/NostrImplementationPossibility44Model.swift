// NostrImplementationPossibility44Model.swift

import Foundation

enum NostrImplementationPossibility44Model {
    static let version: UInt8 = 0x02
    static let nonceByteCount = 32
    static let authenticationCodeByteCount = 32
    static let minimumDecodedPayloadByteCount = 99
    static let minimumEncodedPayloadByteCount = 132
    static let standardMaximumPlaintextByteCount = Int(UInt32.max)

    struct MessageKeys: Sendable, Equatable {
        let chachaKey: Data
        let chachaNonce: Data
        let authenticationKey: Data
    }

    struct ParsedPayload: Sendable, Equatable {
        let nonce: Data
        let ciphertext: Data
        let authenticationCode: Data
    }

    static func deriveConversationKey(
        sharedPointXCoordinate: Data
    ) -> Data {
        HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model.hash(
            sharedPointXCoordinate,
            key: Data("nip44-v2".utf8)
        )
    }

    static func encrypt(
        plaintext: String,
        conversationKey: Data,
        nonce: Data,
        maximumPlaintextByteCount: Int
    ) throws -> String {
        let plaintextByteCount = plaintext.utf8.count
        try validatePlaintextByteCount(
            plaintextByteCount,
            maximumPlaintextByteCount: maximumPlaintextByteCount
        )
        let plaintextBytes = Data(plaintext.utf8)
        let keys = deriveMessageKeys(
            conversationKey: conversationKey,
            nonce: nonce
        )
        let paddedPlaintext = try pad(plaintextBytes)
        let ciphertext = ChaCha20Model.crypt(
            paddedPlaintext,
            key: keys.chachaKey,
            nonce: keys.chachaNonce
        )
        let authenticationCode = authenticationCode(
            ciphertext: ciphertext,
            nonce: nonce,
            key: keys.authenticationKey
        )
        let payload = Data([version]) + nonce + ciphertext + authenticationCode
        return payload.base64EncodedString()
    }

    static func decrypt(
        encodedPayload: String,
        conversationKey: Data,
        maximumEncodedPayloadByteCount: Int,
        maximumPlaintextByteCount: Int
    ) throws -> String {
        try validateMaximumPlaintextByteCount(maximumPlaintextByteCount)
        let payload = try parsePayload(
            encodedPayload,
            maximumEncodedPayloadByteCount: maximumEncodedPayloadByteCount
        )
        let maximumCiphertextByteCount =
            paddedPlaintextByteCount(maximumPlaintextByteCount)
            + (maximumPlaintextByteCount < 65_536 ? 2 : 6)
        guard payload.ciphertext.count <= maximumCiphertextByteCount else {
            throw Error.invalidPayload
        }
        let keys = deriveMessageKeys(
            conversationKey: conversationKey,
            nonce: payload.nonce
        )
        let expectedAuthenticationCode = authenticationCode(
            ciphertext: payload.ciphertext,
            nonce: payload.nonce,
            key: keys.authenticationKey
        )
        guard expectedAuthenticationCode.constantTimeEquals(
            payload.authenticationCode
        ) else {
            throw Error.authenticationFailed
        }
        let paddedPlaintext = ChaCha20Model.crypt(
            payload.ciphertext,
            key: keys.chachaKey,
            nonce: keys.chachaNonce
        )
        let plaintext = try unpad(
            paddedPlaintext,
            maximumPlaintextByteCount: maximumPlaintextByteCount
        )
        guard let decoded = String(data: plaintext, encoding: .utf8) else {
            throw Error.invalidUTF8
        }
        return decoded
    }
}
