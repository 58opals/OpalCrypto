// OpalCrypto+Communication.swift

import Foundation

extension OpalCrypto {
    public enum Communication {

        public static func encrypt(
            message: Data,
            recipientPublicKey: OpalCrypto.Secp256k1.PublicKey,
            paddedPlaintextLength: Int? = nil
        ) throws -> Ciphertext {
            let fields = [
                OpalCryptoDiagnostics.operationField("encrypt"),
                OpalCryptoDiagnostics.publicField("plaintext_byte_count", message.count),
                OpalCryptoDiagnostics.publicField("recipient_public_key_byte_count", recipientPublicKey.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("padded_plaintext_length", paddedPlaintextLength ?? 0),
                OpalCryptoDiagnostics.publicField("has_explicit_padding", paddedPlaintextLength != nil)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.communicationEncryptBegin,
                category: OpalCryptoDiagnostics.Category.communication,
                fields: fields
            )
            do {
                let ciphertext = try CommunicationBoxModel.encrypt(
                    message: message,
                    recipientPublicKey: recipientPublicKey.rawRepresentation,
                    paddedPlaintextLength: paddedPlaintextLength
                )
                let result = Ciphertext(unchecked: ciphertext)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationEncryptSucceeded,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + [
                        OpalCryptoDiagnostics.ciphertextLengthField(result.rawRepresentation.count)
                    ]
                )
                return result
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationEncryptFailed,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> DecryptionResult {
            let fields = [
                OpalCryptoDiagnostics.operationField("decrypt"),
                OpalCryptoDiagnostics.publicField("mode", "private_key"),
                OpalCryptoDiagnostics.ciphertextLengthField(ciphertext.rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.communicationDecryptBegin,
                category: OpalCryptoDiagnostics.Category.communication,
                fields: fields
            )
            do {
                let result = DecryptionResult(
                    resultModel: try CommunicationBoxModel.decrypt(
                        ciphertext.rawRepresentation,
                        privateKey: privateKey.rawRepresentation
                    )
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationDecryptSucceeded,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("plaintext_byte_count", result.message.count),
                        OpalCryptoDiagnostics.publicField("symmetric_key_byte_count", result.symmetricKey.rawRepresentation.count)
                    ]
                )
                return result
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationDecryptFailed,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            symmetricKey: SymmetricKey
        ) throws -> Data {
            let fields = [
                OpalCryptoDiagnostics.operationField("decrypt"),
                OpalCryptoDiagnostics.publicField("mode", "symmetric_key"),
                OpalCryptoDiagnostics.ciphertextLengthField(ciphertext.rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.communicationDecryptBegin,
                category: OpalCryptoDiagnostics.Category.communication,
                fields: fields
            )
            do {
                let message = try CommunicationBoxModel.decrypt(
                    ciphertext.rawRepresentation,
                    symmetricKey: symmetricKey.rawRepresentation
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationDecryptSucceeded,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("plaintext_byte_count", message.count)
                    ]
                )
                return message
            } catch let error as CommunicationBoxModel.Error {
                let mappedError = mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationDecryptFailed,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        private static func mapError(_ error: CommunicationBoxModel.Error) -> Error {
            switch error {
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
