// OpalCrypto.Signature~Verification.swift

import Foundation

extension OpalCrypto.Signature {
    static func verifyValidated(
        signature: Data,
        message: Data,
        verificationKey: VerificationKey,
        format: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormat
    ) throws -> Bool {
        do {
            return try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                signature: signature,
                message: message,
                verificationKeyModel: verificationKey.verificationKeyModel,
                format: format
            )
        } catch {
            if isInvalidVerificationSignatureError(error) {
                return false
            }
            throw mapCryptographyError(error)
        }
    }

    static func isInvalidVerificationSignatureError(_ error: Swift.Error) -> Bool {
        if let secpError = error as? StandardsForEfficientCryptography256k1CurveModel.Error {
            switch secpError {
            case .invalidSignatureLength,
                 .invalidSignatureScalar,
                 .signatureComponentZero,
                 .derMalformed,
                 .derNonCanonical:
                return true
            case .invalidDigestLength,
                 .invalidPrivateKeyLength,
                 .invalidPrivateKeyValue,
                 .invalidPublicKeyLength,
                 .randomGenerationFailed:
                return false
            }
        }

        if let secpFacadeError = error as? OpalCrypto.Secp256k1.Error {
            switch secpFacadeError {
            case .invalidSignatureLength,
                 .invalidSignature,
                 .invalidDER,
                 .nonCanonicalDER:
                return true
            case .invalidPrivateKeyLength,
                 .invalidPrivateKey,
                 .invalidPublicKeyLength,
                 .invalidPublicKeyPrefix,
                 .invalidPublicKey,
                 .invalidTweakLength,
                 .invalidTweak,
                 .invalidDerivedKey,
                 .randomGenerationFailed:
                return false
            }
        }

        return false
    }
}
