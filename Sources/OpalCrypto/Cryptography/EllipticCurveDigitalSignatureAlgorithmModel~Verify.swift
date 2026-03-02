// EllipticCurveDigitalSignatureAlgorithmModel~Verify.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal static func verify(
        signature: Data,
        message: Data,
        publicKey: Data,
        format: SignatureFormatModel
    ) throws -> Bool {
        let compressedPublicKey = publicKey
        guard compressedPublicKey.count == 33 else { throw Error.invalidCompressedPublicKeyLength }
        let prefix = compressedPublicKey[0]
        guard prefix == 0x02 || prefix == 0x03 else { throw Error.invalidCompressedPublicKeyPrefix }

        switch format {
        case .ecdsa(let ecdsaFormat):
            let digestData32Bytes = SecureHashAlgorithm256Model.hash(message)
            switch ecdsaFormat {
            case .raw:
                let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                    raw64ByteSignatureData: signature
                )
                return try StandardsForEfficientCryptography256k1CurveModel.verify(
                    signature: ecdsaSignature,
                    digestData32Bytes: digestData32Bytes,
                    publicKey: compressedPublicKey
                )
            case .compact:
                let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                    raw64ByteSignatureData: signature
                )
                return try StandardsForEfficientCryptography256k1CurveModel.verify(
                    signature: ecdsaSignature,
                    digestData32Bytes: digestData32Bytes,
                    publicKey: compressedPublicKey
                )
            case .distinguishedEncodingRules:
                return try StandardsForEfficientCryptography256k1CurveModel.verify(
                    distinguishedEncodingRulesEncodedSignature: signature,
                    digestData32Bytes: digestData32Bytes,
                    publicKey: compressedPublicKey
                )
            }
        case .schnorr:
            guard message.count == 32 else { throw Error.invalidDigestLength(expected: 32, actual: message.count) }
            let schnorrSignature = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: signature)
            return try SchnorrSignatureModel.verify(
                signature: schnorrSignature,
                digestData32Bytes: message,
                publicKey: publicKey
            )
        }
    }

    internal static func verify(
        signature: Data,
        message: EllipticCurveDigitalSignatureAlgorithmModel.MessageModel,
        publicKey: Data,
        format: SignatureFormatModel
    ) throws -> Bool {
        switch format {
        case .ecdsa:
            let signerInputData = try message.makeDataForSignerHashingOnceSecureHashAlgorithm256Internally()
            return try verify(signature: signature, message: signerInputData, publicKey: publicKey, format: format)
        case .schnorr:
            let digestData32Bytes = try message.makeConsensusDigestData32Bytes()
            return try verify(signature: signature, message: digestData32Bytes, publicKey: publicKey, format: .schnorr)
        }
    }

    internal static func detectFormat(signatureCore: Data) -> SignatureFormatModel? {
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
