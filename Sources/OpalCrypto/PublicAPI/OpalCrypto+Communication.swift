// OpalCrypto+Communication.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Communication {

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

        public static func decrypt(
            _ ciphertext: Ciphertext,
            privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> DecryptionResult {
            let fields = decryptFields(
                mode: "private_key",
                ciphertextByteCount: ciphertext.rawRepresentation.count,
                keyLengthField: OpalDiagnostics.Field.publicField(
                    "private_key_byte_count",
                    privateKey.rawRepresentation.count
                )
            )
            recordCommunication(
                event: OpalDiagnostics.Event.communicationDecryptBegin,
                fields: fields
            )
            do {
                let result = DecryptionResult(
                    resultModel: try CommunicationBoxModel.decrypt(
                        ciphertext.rawRepresentation,
                        privateKey: privateKey.rawRepresentation
                    )
                )
                recordCommunication(
                    event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("plaintext_byte_count", result.message.count),
                        OpalDiagnostics.Field.publicField("symmetric_key_byte_count", result.symmetricKey.rawRepresentation.count)
                    ]
                )
                return result
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                recordCommunicationFailed(
                    event: OpalDiagnostics.Event.communicationDecryptFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            symmetricKey: SymmetricKey
        ) throws -> Data {
            let fields = decryptFields(
                mode: "symmetric_key",
                ciphertextByteCount: ciphertext.rawRepresentation.count,
                keyLengthField: OpalDiagnostics.Field.publicField(
                    "symmetric_key_byte_count",
                    symmetricKey.rawRepresentation.count
                )
            )
            recordCommunication(
                event: OpalDiagnostics.Event.communicationDecryptBegin,
                fields: fields
            )
            do {
                let message = try CommunicationBoxModel.decrypt(
                    ciphertext.rawRepresentation,
                    symmetricKey: symmetricKey.rawRepresentation
                )
                recordCommunication(
                    event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("plaintext_byte_count", message.count)
                    ]
                )
                return message
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                recordCommunicationFailed(
                    event: OpalDiagnostics.Event.communicationDecryptFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
        }

        private static func recordCommunication(
            event: OpalDiagnostics.Event,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: event,
                level: .opalCryptoDefault(for: event),
                fields: fields
            )
        }

        private static func recordCommunicationFailed(
            event: OpalDiagnostics.Event,
            error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            recordCommunication(
                event: event,
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
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

        private static func mapError(_ error: CommunicationBoxModel.Error) -> Error {
            switch error {
            case .invalidMessageLength(let actual):
                return .messageTooLong(maximum: Int(UInt32.max), actual: actual)
            case .messageTooLong(let actual):
                return .messageTooLong(maximum: Int(UInt32.max), actual: actual)
            case .invalidPublicKeyLength(let expected, let actual):
                return .invalidPublicKeyLength(expected: expected, actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidSymmetricKeyLength(let actual):
                return .invalidSymmetricKeyLength(expected: 32, actual: actual)
            case .invalidPaddedPlaintextLength(let minimum, let actual):
                return .invalidPaddedPlaintextLength(minimum: minimum, actual: actual)
            case .paddedPlaintextLengthNotMultipleOf16(let actual):
                return .paddedPlaintextLengthMustBeMultipleOf16(actual: actual)
            case .invalidCiphertext:
                return .invalidCiphertext
            case .cryptographyFailure:
                return .cryptographyFailure
            }
        }

        private static func decryptFields(
            mode: String,
            ciphertextByteCount: Int,
            keyLengthField: OpalDiagnostics.Field
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("decrypt"),
                OpalDiagnostics.Field.publicField("mode", mode),
                OpalDiagnostics.Field.ciphertextLengthField(ciphertextByteCount),
                OpalDiagnostics.Field.publicField(
                    "minimum_ciphertext_byte_count",
                    CommunicationBoxModel.minimumCiphertextLength
                ),
                keyLengthField
            ]
        }
    }
}
