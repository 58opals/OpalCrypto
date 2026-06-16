// OpalCrypto.Communication~Diagnostics.swift

import Foundation
import OpalDiagnostics


extension OpalCrypto.Communication {
    static func recordCommunication(
        event: OpalDiagnostics.Event,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
            event: event,
            level: .opalCryptoDefault(for: event),
            fields: fields
        )
    }

    static func recordCommunicationFailed(
        event: OpalDiagnostics.Event,
        error: Swift.Error,
        fields: [OpalDiagnostics.Field]
    ) {
        recordCommunication(
            event: event,
            fields: fields + OpalDiagnostics.Field.errorFields(error)
        )
    }

    static func mapError(_ error: CommunicationBoxModel.Error) -> Error {
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
