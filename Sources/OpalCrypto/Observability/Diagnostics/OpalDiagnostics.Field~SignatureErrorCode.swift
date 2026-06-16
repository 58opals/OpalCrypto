// OpalDiagnostics.Field~SignatureErrorCode.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func secp256k1ErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Secp256k1.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Secp256k1.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Secp256k1.Error.invalidTweakLength:
            OpalDiagnostics.ErrorCode.invalidTweakLength
        case OpalCrypto.Secp256k1.Error.invalidTweak:
            OpalDiagnostics.ErrorCode.invalidTweak
        case OpalCrypto.Secp256k1.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey
        case OpalCrypto.Secp256k1.Error.invalidSignatureLength:
            OpalDiagnostics.ErrorCode.invalidSignatureLength
        case OpalCrypto.Secp256k1.Error.invalidSignature:
            OpalDiagnostics.ErrorCode.invalidSignature
        case OpalCrypto.Secp256k1.Error.invalidDER:
            OpalDiagnostics.ErrorCode.invalidDER
        case OpalCrypto.Secp256k1.Error.nonCanonicalDER:
            OpalDiagnostics.ErrorCode.nonCanonicalDER
        case OpalCrypto.Secp256k1.Error.randomGenerationFailed:
            OpalDiagnostics.ErrorCode.randomGenerationFailed
        default:
            nil
        }
    }

    static func signatureErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Signature.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Signature.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Signature.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Signature.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Signature.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Signature.Error.invalidDigestLength:
            OpalDiagnostics.ErrorCode.invalidDigestLength
        case OpalCrypto.Signature.Error.invalidSignatureLength:
            OpalDiagnostics.ErrorCode.invalidSignatureLength
        case OpalCrypto.Signature.Error.invalidSignature:
            OpalDiagnostics.ErrorCode.invalidSignature
        case OpalCrypto.Signature.Error.invalidDER:
            OpalDiagnostics.ErrorCode.invalidDER
        case OpalCrypto.Signature.Error.nonCanonicalDER:
            OpalDiagnostics.ErrorCode.nonCanonicalDER
        case OpalCrypto.Signature.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure
        default:
            nil
        }
    }

    static func verificationKeyErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        default:
            nil
        }
    }
}
