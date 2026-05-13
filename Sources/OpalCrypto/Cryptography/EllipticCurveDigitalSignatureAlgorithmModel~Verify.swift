// EllipticCurveDigitalSignatureAlgorithmModel~Verify.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal static func verify(
        signature: Data,
        message: Data,
        publicKey: Data,
        format: SignatureFormat
    ) throws -> Bool {
        let verificationKeyModel = try makeCompressedVerificationKeyModel(
            publicKey: publicKey
        )
        return try verify(
            signature: signature,
            message: message,
            verificationKeyModel: verificationKeyModel,
            format: format
        )
    }

    internal static func verify(
        signature: Data,
        message: Data,
        verificationKeyModel: VerificationKeyModel,
        format: SignatureFormat
    ) throws -> Bool {
        switch format {
        case .ecdsa(let ecdsaFormat):
            let digestData32Bytes = SecureHashAlgorithm256Model.hash(message)
            return try verifyEllipticCurveDigitalSignatureAlgorithm(
                signature: signature,
                digestData32Bytes: digestData32Bytes,
                verificationKeyModel: verificationKeyModel,
                format: ecdsaFormat
            )
        case .schnorr:
            guard message.count == 32 else { throw Error.invalidDigestLength(expected: 32, actual: message.count) }
            let schnorrSignature = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: signature)
            return try SchnorrSignatureModel.verify(
                signature: schnorrSignature,
                digestData32Bytes: message,
                verificationKeyModel: verificationKeyModel
            )
        }
    }

    internal static func verify(
        signature: Data,
        message: EllipticCurveDigitalSignatureAlgorithmModel.Message,
        publicKey: Data,
        format: SignatureFormat
    ) throws -> Bool {
        switch format {
        case .ecdsa(let ecdsaFormat):
            let verificationKeyModel = try makeCompressedVerificationKeyModel(
                publicKey: publicKey
            )
            let digestData32Bytes = try message.makeEllipticCurveDigitalSignatureAlgorithmDigestData32Bytes()
            return try verifyEllipticCurveDigitalSignatureAlgorithm(
                signature: signature,
                digestData32Bytes: digestData32Bytes,
                verificationKeyModel: verificationKeyModel,
                format: ecdsaFormat
            )
        case .schnorr:
            let digestData32Bytes = try message.makeConsensusDigestData32Bytes()
            return try verify(signature: signature, message: digestData32Bytes, publicKey: publicKey, format: .schnorr)
        }
    }

    internal static func detectFormat(signatureCore: Data) -> SignatureFormat? {
        if signatureCore.count == 64 { return .schnorr }
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                distinguishedEncodingRulesEncoded: signatureCore
            )
            return .ecdsa(.distinguishedEncodingRules)
        } catch {
            return nil
        }
    }
}

private extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func makeCompressedVerificationKeyModel(
        publicKey: Data
    ) throws -> VerificationKeyModel {
        guard publicKey.count == 33 else {
            throw Error.invalidCompressedPublicKeyLength(expected: 33, actual: publicKey.count)
        }
        guard let prefix = publicKey.first else {
            throw Error.invalidCompressedPublicKeyLength(expected: 33, actual: publicKey.count)
        }
        guard prefix == 0x02 || prefix == 0x03 else {
            throw Error.invalidCompressedPublicKeyPrefix(actual: prefix)
        }
        return try StandardsForEfficientCryptography256k1CurveModel.Operation
            .makeVerificationKey(publicKey: publicKey)
    }

    static func verifyEllipticCurveDigitalSignatureAlgorithm(
        signature: Data,
        digestData32Bytes: Data,
        verificationKeyModel: VerificationKeyModel,
        format: SignatureFormat.EllipticCurveDigitalSignatureAlgorithm
    ) throws -> Bool {
        switch format {
        case .raw, .compact:
            let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                raw64ByteSignatureData: signature
            )
            return try StandardsForEfficientCryptography256k1CurveModel.verify(
                signature: ecdsaSignature,
                digestData32Bytes: digestData32Bytes,
                verificationKeyModel: verificationKeyModel
            )
        case .distinguishedEncodingRules:
            return try StandardsForEfficientCryptography256k1CurveModel.verify(
                distinguishedEncodingRulesEncodedSignature: signature,
                digestData32Bytes: digestData32Bytes,
                verificationKeyModel: verificationKeyModel
            )
        }
    }
}
