// EllipticCurveDigitalSignatureAlgorithmModel.swift

import Foundation

public struct EllipticCurveDigitalSignatureAlgorithmModel {
    static func add(to compressedPublicKey: Data, tweak: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.OperationModel.tweakAddPublicKey(compressedPublicKey,
                                                  tweak32: tweak,
                                                  format: .compressed)
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    enum Error: Swift.Error {
        case invalidCompressedPublicKeyLength
        case invalidCompressedPublicKeyPrefix
        case invalidDigestLength(expected: Int, actual: Int)
        case invalidHashIterationCount
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func derivePublicKey(from privateKey: Data) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.OperationModel.derivePublicKey(fromPrivateKey32: privateKey, format: .compressed)
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    public enum SignatureFormatModel: Sendable {
        /// Signature wire-format used by signing and verification.
        /// - Note:
        ///   - **OP_CHECKSIG + EllipticCurveDigitalSignatureAlgorithmModel requires DistinguishedEncodingRulesModel**. Using `.raw` or `.compact` with CHECKSIG is invalid at consensus.
        ///   - SchnorrSignatureModel is allowed for CHECKSIG as per BCH consensus.
        case ecdsa(EllipticCurveDigitalSignatureAlgorithmModel)
        case schnorr // Bitcoin Cash SchnorrSignatureModel (May 2019+).
        
        public enum EllipticCurveDigitalSignatureAlgorithmModel: Sendable {
            case raw
            case compact
            case der
        }
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func sign(message: Data,
                     with privateKey: Data,
                     in format: SignatureFormatModel,
                     nonceFunction: NonceGenerationPolicy = .rfc6979BchDefault) throws -> Data {
        switch format {
        case .ecdsa(let ecdsa):
            let digest32 = SecureHashAlgorithm256Model.hash(message)
            let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.sign(digest32: digest32,
                                                    privateKey32: privateKey,
                                                    nonce: makeEcdsaNonce(from: nonceFunction))
            switch ecdsa {
            case .raw:
                return ecdsaSignature.raw64
            case .compact:
                return ecdsaSignature.raw64
            case .der:
                return try ecdsaSignature.encodeDER()
            }
        case .schnorr:
            guard message.count == 32 else { throw Error.invalidDigestLength(expected: 32, actual: message.count) }
            let signature = try SchnorrSignatureModel.sign(digest32: message,
                                             privateKey32: privateKey,
                                             nonce: nonceFunction)
            return signature.raw64
        }
    }
    
    static func sign(message: EllipticCurveDigitalSignatureAlgorithmModel.MessageModel,
                     with privateKey: Data,
                     in format: SignatureFormatModel,
                     nonceFunction: NonceGenerationPolicy = .rfc6979BchDefault) throws -> Data {
        switch format {
        case .ecdsa:
            let signerInput = try message.makeDataForSignerHashingOnceSHA256Internally()
            return try sign(message: signerInput, with: privateKey, in: format, nonceFunction: nonceFunction)
        case .schnorr:
            let digest32 = try message.makeConsensusDigest32()
            return try sign(message: digest32, with: privateKey, in: .schnorr, nonceFunction: nonceFunction)
        }
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func verify(signature: Data, message: Data, publicKey: Data, format: SignatureFormatModel) throws -> Bool {
        let compressedPublicKey = publicKey
        guard compressedPublicKey.count == 33 else { throw Error.invalidCompressedPublicKeyLength }
        let prefix = compressedPublicKey[0]
        guard prefix == 0x02 || prefix == 0x03 else { throw Error.invalidCompressedPublicKeyPrefix }
        
        switch format {
        case .ecdsa(let ecdsa):
            let digest32 = SecureHashAlgorithm256Model.hash(message)
            switch ecdsa {
            case .raw:
                let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.Signature(raw64: signature)
                return try StandardsForEfficientCryptography256k1CurveModel.verify(signature: ecdsaSignature, digest32: digest32, publicKey: compressedPublicKey)
            case .compact:
                let ecdsaSignature = try StandardsForEfficientCryptography256k1CurveModel.Signature(raw64: signature)
                return try StandardsForEfficientCryptography256k1CurveModel.verify(signature: ecdsaSignature, digest32: digest32, publicKey: compressedPublicKey)
            case .der:
                return try StandardsForEfficientCryptography256k1CurveModel.verify(derEncodedSignature: signature,
                                            digest32: digest32,
                                            publicKey: compressedPublicKey)
            }
        case .schnorr:
            do {
                guard message.count == 32 else { throw Error.invalidDigestLength(expected: 32, actual: message.count) }
                let schnorrSignature = try SchnorrSignatureModel.Signature(raw64: signature)
                return try SchnorrSignatureModel.verify(signature: schnorrSignature,
                                          digest32: message,
                                          publicKey: publicKey)
            } catch {
                return false
            }
        }
    }
    
    static func verify(signature: Data, message: EllipticCurveDigitalSignatureAlgorithmModel.MessageModel, publicKey: Data, format: SignatureFormatModel) throws -> Bool {
        switch format {
        case .ecdsa:
            let signerInput = try message.makeDataForSignerHashingOnceSHA256Internally()
            return try verify(signature: signature, message: signerInput, publicKey: publicKey, format: format)
        case .schnorr:
            let digest32 = try message.makeConsensusDigest32()
            return try verify(signature: signature, message: digest32, publicKey: publicKey, format: .schnorr)
        }
    }
}

extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func detectFormat(signatureCore: Data) -> SignatureFormatModel? {
        if signatureCore.count == 64 { return .schnorr }
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Signature(derEncoded: signatureCore)
            return .ecdsa(.der)
        } catch {
            return nil
        }
    }
}

private extension EllipticCurveDigitalSignatureAlgorithmModel {
    static func makeEcdsaNonce(from nonceFunction: NonceGenerationPolicy) -> NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel {
        switch nonceFunction {
        case .systemRandom:
            return .systemRandom
        case .rfc6979BchDefault, .bipSchnorrDeterministic:
            return .rfc6979Sha256
        }
    }
}
