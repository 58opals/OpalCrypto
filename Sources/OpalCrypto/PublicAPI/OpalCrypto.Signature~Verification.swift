// OpalCrypto.Signature~Verification.swift

import Foundation

extension OpalCrypto.Signature {
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

        return false
    }
}
