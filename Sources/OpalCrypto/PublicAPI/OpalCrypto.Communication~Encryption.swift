// OpalCrypto.Communication~Encryption.swift

import Foundation
import OpalDiagnostics


extension OpalCrypto.Communication {
    /// Encrypts a message for a recipient and returns its authenticated ciphertext envelope.
    ///
    /// The plaintext contains a four-byte message-length prefix followed by the message and zero padding. When `paddedPlaintextLength` is omitted, the plaintext expands to the smallest multiple of 16 that can contain the prefix and message. An explicit length must be at least `message.count + 4` and a multiple of 16.
    ///
    /// - Throws: ``OpalCrypto/Communication/Error/messageTooLong(maximum:actual:)`` when the message cannot fit in the 32-bit length prefix, or padding and cryptographic errors reported by ``OpalCrypto/Communication/Error``.
    public static func encrypt(
        message: Data,
        recipientPublicKey: OpalCrypto.Secp256k1.PublicKey,
        paddedPlaintextLength: Int? = nil
    ) throws -> Ciphertext {
        let fields = encryptFields(
            message: message,
            recipientPublicKey: recipientPublicKey,
            paddedPlaintextLength: paddedPlaintextLength
        )
        recordCommunication(
            event: OpalDiagnostics.Event.communicationEncryptBegin,
            fields: fields
        )
        do {
            let ciphertext = try CommunicationBoxModel.encrypt(
                message: message,
                recipientPublicKey: recipientPublicKey.rawRepresentation,
                paddedPlaintextLength: paddedPlaintextLength
            )
            let result = Ciphertext(unchecked: ciphertext)
            recordCommunication(
                event: OpalDiagnostics.Event.communicationEncryptSucceeded,
                fields: fields + [
                    OpalDiagnostics.Field.ciphertextLengthField(result.rawRepresentation.count)
                ]
            )
            return result
        } catch let error as CommunicationBoxModel.Error {
            let mappedError = mapError(error)
            recordCommunicationFailed(
                event: OpalDiagnostics.Event.communicationEncryptFailed,
                error: mappedError,
                fields: fields
            )
            throw mappedError
        }
    }

    private static func encryptFields(
        message: Data,
        recipientPublicKey: OpalCrypto.Secp256k1.PublicKey,
        paddedPlaintextLength: Int?
    ) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.operationField("encrypt"),
            OpalDiagnostics.Field.publicField("plaintext_byte_count", message.count),
            OpalDiagnostics.Field.publicField(
                "recipient_public_key_byte_count",
                recipientPublicKey.rawRepresentation.count
            ),
            OpalDiagnostics.Field.publicField("minimum_padded_plaintext_length", message.count + 4),
            OpalDiagnostics.Field.publicField(
                "padded_plaintext_length",
                reportedPaddedPlaintextLength(
                    messageByteCount: message.count,
                    paddedPlaintextLength: paddedPlaintextLength
                )
            ),
            OpalDiagnostics.Field.publicField("has_explicit_padding", paddedPlaintextLength != nil)
        ]
    }

    private static func reportedPaddedPlaintextLength(
        messageByteCount: Int,
        paddedPlaintextLength: Int?
    ) -> Int {
        paddedPlaintextLength
            ?? (try? CommunicationBoxModel.resolvePlaintextLength(
                messageByteCount: messageByteCount,
                paddedPlaintextLength: nil
            ))
            ?? 0
    }
}
