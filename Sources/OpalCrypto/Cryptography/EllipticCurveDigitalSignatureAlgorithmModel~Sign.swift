// EllipticCurveDigitalSignatureAlgorithmModel~Sign.swift

import Foundation

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal static func add(to compressedPublicKeyData: Data, tweakData: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.Operation.tweakAddPublicKey(
            compressedPublicKeyData,
            tweakData32Bytes: tweakData,
            format: .compressed
        )
    }

    internal static func derivePublicKey(from privateKeyData: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
            fromPrivateKeyData32Bytes: privateKeyData,
            format: .compressed
        )
    }

    internal static func sign(
        message: Data,
        with privateKeyData: Data,
        in format: SignatureFormat,
        nonceFunction: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Data {
        switch format {
        case .ecdsa(let ecdsaFormat):
            let digestData32Bytes = SecureHashAlgorithm256Model.hash(message)
            return try signEllipticCurveDigitalSignatureAlgorithm(
                digestData32Bytes: digestData32Bytes,
                privateKeyData32Bytes: privateKeyData,
                format: ecdsaFormat,
                nonce: makeEcdsaNonce(from: nonceFunction)
            )
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
        message: EllipticCurveDigitalSignatureAlgorithmModel.Message,
        with privateKeyData: Data,
        in format: SignatureFormat,
        nonceFunction: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Data {
        switch format {
        case .ecdsa(let ecdsaFormat):
            let digestData32Bytes = try message.makeEllipticCurveDigitalSignatureAlgorithmDigestData32Bytes()
            return try signEllipticCurveDigitalSignatureAlgorithm(
                digestData32Bytes: digestData32Bytes,
                privateKeyData32Bytes: privateKeyData,
                format: ecdsaFormat,
                nonce: makeEcdsaNonce(from: nonceFunction)
            )
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
    static func signEllipticCurveDigitalSignatureAlgorithm(
        digestData32Bytes: Data,
        privateKeyData32Bytes: Data,
        format: SignatureFormat.EllipticCurveDigitalSignatureAlgorithm,
        nonce: NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel
    ) throws -> Data {
        let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.sign(
            digestData32Bytes: digestData32Bytes,
            privateKeyData32Bytes: privateKeyData32Bytes,
            nonce: nonce
        )
        switch format {
        case .raw, .compact:
            return ecdsaSignature.raw64ByteSignatureData
        case .distinguishedEncodingRules:
            return try ecdsaSignature.encodeDistinguishedEncodingRules()
        }
    }

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
