// OpalCrypto+Communication.swift

import Foundation

extension OpalCrypto {
    public enum Communication {

        public static func encrypt(
            message: Data,
            recipientPublicKey: OpalCrypto.Secp256k1.PublicKey,
            paddedPlaintextLength: Int? = nil
        ) throws -> Ciphertext {
            do {
                let ciphertext = try CommunicationBoxModel.encrypt(
                    message: message,
                    recipientPublicKey: recipientPublicKey.rawRepresentation,
                    paddedPlaintextLength: paddedPlaintextLength
                )
                return Ciphertext(unchecked: ciphertext)
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> DecryptionResult {
            do {
                return DecryptionResult(
                    resultModel: try CommunicationBoxModel.decrypt(
                        ciphertext.rawRepresentation,
                        privateKey: privateKey.rawRepresentation
                    )
                )
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
            }
        }

        public static func decrypt(
            _ ciphertext: Ciphertext,
            symmetricKey: SymmetricKey
        ) throws -> Data {
            do {
                return try CommunicationBoxModel.decrypt(
                    ciphertext.rawRepresentation,
                    symmetricKey: symmetricKey.rawRepresentation
                )
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
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
