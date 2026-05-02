// OpalCrypto+BlindSignature.swift

import Foundation

extension OpalCrypto {
    public enum BlindSignature {

        static func mapError(_ error: BlindSignatureModel.Error) -> Error {
            switch error {
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            case .invalidNoncePointLength(let actual):
                return .invalidNoncePointLength(actual: actual)
            case .invalidNoncePointPrefix(let actual):
                return .invalidNoncePointPrefix(actual: actual)
            case .invalidNoncePoint:
                return .invalidNoncePoint
            case .invalidDigestLength(let actual):
                return .invalidDigestLength(expected: 32, actual: actual)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidRequestLength(let actual):
                return .invalidRequestLength(expected: 32, actual: actual)
            case .invalidRequestScalar:
                return .invalidRequestScalar
            case .invalidResponseLength(let actual):
                return .invalidResponseLength(expected: 32, actual: actual)
            case .invalidResponseScalar:
                return .invalidResponseScalar
            case .nonceAlreadyUsed:
                return .nonceAlreadyUsed
            case .randomGenerationFailed, .cryptographyFailure:
                return .cryptographyFailure
            case .verificationFailed:
                return .verificationFailed
            }
        }

        static func mapSecp256k1Error(_ error: OpalCrypto.Secp256k1.Error) -> Error {
            switch error {
            case .invalidPrivateKeyLength(let expected, let actual):
                return .invalidPrivateKeyLength(expected: expected, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidPublicKeyLength(_, let actual):
                return .invalidPublicKeyLength(actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            case .invalidTweakLength,
                 .invalidTweak,
                 .invalidDerivedKey,
                 .invalidSignatureLength,
                 .invalidSignature,
                 .invalidDER,
                 .nonCanonicalDER,
                 .randomGenerationFailed:
                return .cryptographyFailure
            }
        }
    }
}
