// OpalCrypto.Secp256k1~Validation.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    static func expectedSecp256k1PublicKeyLength(for publicKey: Data) -> Int {
        guard let prefix = publicKey.first else {
            return 33
        }

        switch prefix {
        case 0x04:
            return 65
        case 0x02, 0x03:
            return 33
        default:
            return publicKey.count > 33 ? 65 : 33
        }
    }

    static func validatePrivateKey(_ privateKey: Data) throws {
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Operation.parsePrivateKeyScalar(
                privateKey,
                requireNonZero: true
            )
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
            throw mapOperationError(error)
        }
    }

    static func mapOperationError(
        _ error: StandardsForEfficientCryptography256k1CurveModel.Operation.Error
    ) -> Error {
        switch error {
        case .invalidPrivateKeyLength(let actual):
            return .invalidPrivateKeyLength(expected: 32, actual: actual)
        case .invalidPrivateKeyValue:
            return .invalidPrivateKey
        case .invalidPublicKeyLength(let actual):
            return .invalidPublicKeyLength(expected: 33, actual: actual)
        case .invalidPublicKeyValue:
            return .invalidPublicKey
        case .invalidTweakLength(let actual):
            return .invalidTweakLength(expected: 32, actual: actual)
        case .invalidTweakValue:
            return .invalidTweak
        case .invalidDerivedPrivateKey, .invalidDerivedPublicKey:
            return .invalidDerivedKey
        case .randomGenerationFailed(let status):
            return .randomGenerationFailed(status: status)
        }
    }
}
