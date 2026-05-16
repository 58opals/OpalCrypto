// OpalCrypto.Signature~ErrorMapping.swift

import Foundation

extension OpalCrypto.Signature {
    static func mapCryptographyError(_ error: Swift.Error) -> Error {
        if let signatureError = error as? EllipticCurveDigitalSignatureAlgorithmModel.Error {
            switch signatureError {
            case .invalidCompressedPublicKeyLength(let expected, let actual):
                return .invalidPublicKeyLength(expected: expected, actual: actual)
            case .invalidCompressedPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidDigestLength(let expected, let actual):
                return .invalidDigestLength(expected: expected, actual: actual)
            case .invalidHashIterationCount:
                return .cryptographyFailure
            }
        }

        if let schnorrError = error as? SchnorrSignatureModel.Error {
            switch schnorrError {
            case .invalidDigestLength(let actual):
                return .invalidDigestLength(expected: 32, actual: actual)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
            case .invalidSignatureLength(let actual):
                return .invalidSignatureLength(expected: 64, actual: actual)
            case .invalidPrivateKeyValue:
                return .invalidPrivateKey
            case .randomGenerationFailed:
                return .cryptographyFailure
            }
        }

        if let secpError = error as? StandardsForEfficientCryptography256k1CurveModel.Error {
            switch secpError {
            case .invalidDigestLength(let actual):
                return .invalidDigestLength(expected: 32, actual: actual)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
            case .invalidSignatureLength(let actual):
                return .invalidSignatureLength(expected: 64, actual: actual)
            case .invalidPrivateKeyValue:
                return .invalidPrivateKey
            case .invalidSignatureScalar,
                 .signatureComponentZero,
                 .derMalformed,
                 .derNonCanonical,
                 .randomGenerationFailed:
                return .cryptographyFailure
            }
        }

        if let secpFacadeError = error as? OpalCrypto.Secp256k1.Error {
            switch secpFacadeError {
            case .invalidPrivateKeyLength(let expected, let actual):
                return .invalidPrivateKeyLength(expected: expected, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidDerivedKey:
                return .cryptographyFailure
            case .invalidPublicKeyLength(let expected, let actual):
                return .invalidPublicKeyLength(expected: expected, actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            case .invalidTweakLength,
                 .invalidTweak,
                 .invalidSignatureLength,
                 .invalidSignature,
                 .invalidDER,
                 .nonCanonicalDER,
                 .randomGenerationFailed:
                return .cryptographyFailure
            }
        }

        return .cryptographyFailure
    }

    static func mapDiagnosticsError(_ error: Swift.Error) -> Error {
        if let facadeError = error as? Error {
            return facadeError
        }

        return mapCryptographyError(error)
    }

    static func mapVerificationKeyError(
        _ error: VerificationKey.Error
    ) -> Error {
        switch error {
        case .invalidPublicKeyLength(let actual):
            return .invalidPublicKeyLength(expected: 33, actual: actual)
        case .invalidPublicKeyPrefix(let actual):
            return .invalidPublicKeyPrefix(actual: actual)
        case .invalidPublicKey:
            return .invalidPublicKey
        }
    }
}
