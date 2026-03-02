// EllipticCurveDigitalSignatureAlgorithmModel~Sign.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal static func add(to compressedPublicKeyData: Data, tweakData: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.OperationModel.tweakAddPublicKey(
            compressedPublicKeyData,
            tweakData32Bytes: tweakData,
            format: .compressed
        )
    }

    internal static func derivePublicKey(from privateKeyData: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.OperationModel.derivePublicKey(
            fromPrivateKeyData32Bytes: privateKeyData,
            format: .compressed
        )
    }

    internal static func sign(
        message: Data,
        with privateKeyData: Data,
        in format: SignatureFormatModel,
        nonceFunction: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Data {
        switch format {
        case .ecdsa(let ecdsaFormat):
            let digestData32Bytes = SecureHashAlgorithm256Model.hash(message)
            let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.sign(
                digestData32Bytes: digestData32Bytes,
                privateKeyData32Bytes: privateKeyData,
                nonce: makeEcdsaNonce(from: nonceFunction)
            )
            switch ecdsaFormat {
            case .raw:
                return ecdsaSignature.raw64ByteSignatureData
            case .compact:
                return ecdsaSignature.raw64ByteSignatureData
            case .distinguishedEncodingRules:
                return try ecdsaSignature.encodeDistinguishedEncodingRules()
            }
        case .schnorr:
            guard message.count == 32 else { throw Error.invalidDigestLength(expected: 32, actual: message.count) }
            let signature = try SchnorrSignatureModel.sign(
                digestData32Bytes: message,
                privateKeyData32Bytes: privateKeyData,
                nonce: nonceFunction
            )
            return signature.raw64ByteSignatureData
        }
    }

    internal static func sign(
        message: EllipticCurveDigitalSignatureAlgorithmModel.MessageModel,
        with privateKeyData: Data,
        in format: SignatureFormatModel,
        nonceFunction: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Data {
        switch format {
        case .ecdsa:
            let signerInputData = try message.makeDataForSignerHashingOnceSecureHashAlgorithm256Internally()
            return try sign(message: signerInputData, with: privateKeyData, in: format, nonceFunction: nonceFunction)
        case .schnorr:
            let digestData32Bytes = try message.makeConsensusDigestData32Bytes()
            return try sign(
                message: digestData32Bytes,
                with: privateKeyData,
                in: .schnorr,
                nonceFunction: nonceFunction
            )
        }
    }
}

private extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func makeEcdsaNonce(
        from nonceFunction: NonceGenerationPolicy
    ) -> NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel {
        switch nonceFunction {
        case .systemRandom:
            return .systemRandom
        case .requestForComments6979BitcoinCashDefault, .bitcoinImprovementProposalSchnorrDeterministic:
            return .requestForComments6979SecureHashAlgorithm256
        }
    }
}
