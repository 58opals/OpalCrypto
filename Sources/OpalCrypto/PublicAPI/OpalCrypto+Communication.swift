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
            let resolvedPaddedPlaintextLength = paddedPlaintextLength
                ?? (try? CommunicationBoxModel.resolvePlaintextLength(
                    messageByteCount: message.count,
                    paddedPlaintextLength: nil
                ))
                ?? 0
            let fields = [
                OpalDiagnostics.Field.operationField("encrypt"),
                OpalDiagnostics.Field.publicField("plaintext_byte_count", message.count),
                OpalDiagnostics.Field.publicField("recipient_public_key_byte_count", recipientPublicKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("padded_plaintext_length", resolvedPaddedPlaintextLength),
                OpalDiagnostics.Field.publicField("has_explicit_padding", paddedPlaintextLength != nil)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationEncryptBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationEncryptBegin),
                fields: fields
            )
            do {
                let ciphertext = try CommunicationBoxModel.encrypt(
                    message: message,
                    recipientPublicKey: recipientPublicKey.rawRepresentation,
                    paddedPlaintextLength: paddedPlaintextLength
                )
                let result = Ciphertext(unchecked: ciphertext)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationEncryptSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationEncryptSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.ciphertextLengthField(result.rawRepresentation.count)
                    ]
                )
                return result
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationEncryptFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationEncryptFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> DecryptionResult {
            let fields = [
                OpalDiagnostics.Field.operationField("decrypt"),
                OpalDiagnostics.Field.publicField("mode", "private_key"),
                OpalDiagnostics.Field.ciphertextLengthField(ciphertext.rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationDecryptBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptBegin),
                fields: fields
            )
            do {
                let result = DecryptionResult(
                    resultModel: try CommunicationBoxModel.decrypt(
                        ciphertext.rawRepresentation,
                        privateKey: privateKey.rawRepresentation
                    )
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("plaintext_byte_count", result.message.count),
                        OpalDiagnostics.Field.publicField("symmetric_key_byte_count", result.symmetricKey.rawRepresentation.count)
                    ]
                )
                return result
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationDecryptFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            symmetricKey: SymmetricKey
        ) throws -> Data {
            let fields = [
                OpalDiagnostics.Field.operationField("decrypt"),
                OpalDiagnostics.Field.publicField("mode", "symmetric_key"),
                OpalDiagnostics.Field.ciphertextLengthField(ciphertext.rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationDecryptBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptBegin),
                fields: fields
            )
            do {
                let message = try CommunicationBoxModel.decrypt(
                    ciphertext.rawRepresentation,
                    symmetricKey: symmetricKey.rawRepresentation
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("plaintext_byte_count", message.count)
                    ]
                )
                return message
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationDecryptFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationDecryptFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
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
    }
}
