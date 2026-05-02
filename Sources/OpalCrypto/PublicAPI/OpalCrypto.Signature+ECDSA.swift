// OpalCrypto.Signature+ECDSA.swift

import Foundation

extension OpalCrypto.Signature {
    public struct ECDSA: Sendable, Equatable {
        internal let signatureModel: StandardsForEfficientCryptography256k1CurveModel.Signature

        public let format: ECDSAFormat
        public let rawRepresentation: Data

        public init(
            rawRepresentation: Data,
            format: ECDSAFormat
        ) throws {
            self.format = format
            do {
                switch format {
                case .raw:
                    signatureModel = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                        raw64ByteSignatureData: rawRepresentation
                    )
                    self.rawRepresentation = rawRepresentation
                case .der:
                    signatureModel = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                        distinguishedEncodingRulesEncoded: rawRepresentation
                    )
                    self.rawRepresentation = rawRepresentation
                }
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
                throw Self.mapSignatureError(error, format: format)
            }
        }

        internal init(
            signatureModel: StandardsForEfficientCryptography256k1CurveModel.Signature,
            format: ECDSAFormat
        ) throws {
            self.signatureModel = signatureModel
            self.format = format
            switch format {
            case .raw:
                rawRepresentation = signatureModel.raw64ByteSignatureData
            case .der:
                rawRepresentation = try signatureModel.encodeDistinguishedEncodingRules()
            }
        }

        public static func sign(
            message: Data,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            format: ECDSAFormat = .der,
            noncePolicy: ECDSANoncePolicy = .rfc6979
        ) throws -> ECDSA {
            do {
                let signatureData = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: message,
                    with: privateKey.rawRepresentation,
                    in: format.internalFormat,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
                return try ECDSA(rawRepresentation: signatureData, format: format)
            } catch {
                throw OpalCrypto.Signature.mapCryptographyError(error)
            }
        }

        public static func sign(
            digest: Digest,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            format: ECDSAFormat = .der,
            noncePolicy: ECDSANoncePolicy = .rfc6979
        ) throws -> ECDSA {
            do {
                let signatureModel = try StandardsForEfficientCryptography256k1CurveModel
                    .sign(
                        digestData32Bytes: digest.rawRepresentation,
                        privateKeyData32Bytes: privateKey.rawRepresentation,
                        nonce: noncePolicy.internalECDSANoncePolicy
                    )
                return try ECDSA(signatureModel: signatureModel, format: format)
            } catch {
                throw OpalCrypto.Signature.mapCryptographyError(error)
            }
        }

        public func encoded(as format: ECDSAFormat) throws -> ECDSA {
            try ECDSA(signatureModel: signatureModel, format: format)
        }

        public func normalizedLowS() throws -> ECDSA {
            try ECDSA(
                signatureModel: signatureModel.normalizeLowS(),
                format: format
            )
        }

        public var isLowS: Bool {
            signatureModel.isLowS
        }

        public func verify(
            message: Data,
            publicKey: OpalCrypto.Secp256k1.PublicKey
        ) throws -> Bool {
            try verify(
                message: message,
                verificationKey: VerificationKey(publicKey: publicKey)
            )
        }

        public func verify(
            message: Data,
            verificationKey: VerificationKey
        ) throws -> Bool {
            try OpalCrypto.Signature.verifyValidated(
                signature: rawRepresentation,
                message: message,
                verificationKey: verificationKey,
                format: format.internalFormat
            )
        }

        public func verify(
            digest: Digest,
            publicKey: OpalCrypto.Secp256k1.PublicKey
        ) throws -> Bool {
            try verify(
                digest: digest,
                verificationKey: VerificationKey(publicKey: publicKey)
            )
        }

        public func verify(
            digest: Digest,
            verificationKey: VerificationKey
        ) throws -> Bool {
            do {
                return try StandardsForEfficientCryptography256k1CurveModel.verify(
                    signature: signatureModel,
                    digestData32Bytes: digest.rawRepresentation,
                    verificationKeyModel: verificationKey.verificationKeyModel
                )
            } catch {
                if OpalCrypto.Signature.isInvalidVerificationSignatureError(error) {
                    return false
                }
                throw OpalCrypto.Signature.mapCryptographyError(error)
            }
        }

        private static func mapSignatureError(
            _ error: StandardsForEfficientCryptography256k1CurveModel.Error,
            format: ECDSAFormat
        ) -> Error {
            switch error {
            case .invalidSignatureLength(let actual):
                return .invalidSignatureLength(
                    expected: format == .raw ? 64 : actual,
                    actual: actual
                )
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
                return .cryptographyFailure
            }
        }
    }
}

private extension OpalCrypto.Signature.ECDSANoncePolicy {
    var internalECDSANoncePolicy: NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel {
        switch self {
        case .rfc6979:
            return .requestForComments6979SecureHashAlgorithm256
        case .random:
            return .systemRandom
        }
    }
}
