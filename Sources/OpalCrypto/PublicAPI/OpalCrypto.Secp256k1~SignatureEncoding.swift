// OpalCrypto.Secp256k1~SignatureEncoding.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public static func encodeDER(_ rawSignature: Data) throws -> Data {
        try makeSignature(rawSignature).encodeDistinguishedEncodingRules()
    }

    public static func decodeDER(_ derSignature: Data) throws -> Data {
        do {
            return try StandardsForEfficientCryptography256k1CurveModel.Signature(
                distinguishedEncodingRulesEncoded: derSignature
            ).raw64ByteSignatureData
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
            throw mapSignatureError(error)
        }
    }

    public static func normalizeLowS(_ rawSignature: Data) throws -> Data {
        try makeSignature(rawSignature).normalizeLowS().raw64ByteSignatureData
    }

    public static func isLowS(_ rawSignature: Data) throws -> Bool {
        try makeSignature(rawSignature).isLowS
    }

    static func makeSignature(_ rawSignature: Data) throws -> StandardsForEfficientCryptography256k1CurveModel.Signature {
        do {
            return try StandardsForEfficientCryptography256k1CurveModel.Signature(
                raw64ByteSignatureData: rawSignature
            )
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
            throw mapSignatureError(error)
        }
    }

    static func mapSignatureError(
        _ error: StandardsForEfficientCryptography256k1CurveModel.Error
    ) -> Error {
        switch error {
        case .invalidSignatureLength(let actual):
            return .invalidSignatureLength(expected: 64, actual: actual)
        case .signatureComponentZero, .invalidSignatureScalar:
            return .invalidSignature
        case .derMalformed:
            return .invalidDER
        case .derNonCanonical:
            return .nonCanonicalDER
        case .invalidDigestLength,
             .invalidPrivateKeyLength,
             .invalidPrivateKeyValue,
             .invalidPublicKeyLength,
             .randomGenerationFailed:
            return .invalidSignature
        }
    }
}
