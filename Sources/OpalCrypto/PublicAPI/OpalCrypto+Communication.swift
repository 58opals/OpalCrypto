// OpalCrypto+Communication.swift

import Foundation

extension OpalCrypto {
    public enum Communication {
        public enum Error: Swift.Error, Equatable {
            case invalidPublicKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidPublicKey
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPrivateKey
            case invalidSymmetricKeyLength(expected: Int, actual: Int)
            case invalidPaddedPlaintextLength(minimum: Int, actual: Int)
            case paddedPlaintextLengthMustBeMultipleOf16(actual: Int)
            case invalidCiphertext
            case cryptographyFailure
        }

        public struct DecryptionResult: Sendable, Equatable {
            public let message: Data
            public let symmetricKey: Data

            internal init(resultModel: CommunicationBoxModel.DecryptionResult) {
                self.message = resultModel.message
                self.symmetricKey = resultModel.symmetricKey
            }
        }

        public static func encrypt(
            message: Data,
            recipientPublicKey: Data,
            paddedPlaintextLength: Int? = nil
        ) throws -> Data {
            do {
                return try CommunicationBoxModel.encrypt(
                    message: message,
                    recipientPublicKey: recipientPublicKey,
                    paddedPlaintextLength: paddedPlaintextLength
                )
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
            }
        }

        public static func decrypt(
            _ ciphertext: Data,
            privateKey: Data
        ) throws -> DecryptionResult {
            do {
                return DecryptionResult(
                    resultModel: try CommunicationBoxModel.decrypt(
                        ciphertext,
                        privateKey: privateKey
                    )
                )
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
            }
        }

        public static func decrypt(
            _ ciphertext: Data,
            symmetricKey: Data
        ) throws -> Data {
            do {
                return try CommunicationBoxModel.decrypt(
                    ciphertext,
                    symmetricKey: symmetricKey
                )
            } catch let error as CommunicationBoxModel.Error {
                throw mapError(error)
            }
        }

        private static func mapError(_ error: CommunicationBoxModel.Error) -> Error {
            switch error {
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
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
