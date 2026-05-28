// OpalCrypto.Signature+ECDSA.swift

import Foundation
import OpalDiagnostics

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
                    self.rawRepresentation = Data(rawRepresentation)
                case .der:
                    signatureModel = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                        distinguishedEncodingRulesEncoded: rawRepresentation
                    )
                    self.rawRepresentation = Data(rawRepresentation)
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
            let fields = signFields(
                format: format,
                noncePolicy: noncePolicy,
                privateKey: privateKey,
                payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count)
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaSignBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignBegin),
                fields: fields
            )
            do {
                let signatureData = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: message,
                    with: privateKey.rawRepresentation,
                    in: format.internalFormat,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
                let signature = try ECDSA(rawRepresentation: signatureData, format: format)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaSignSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaSignFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func sign(
            digest: Digest,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            format: ECDSAFormat = .der,
            noncePolicy: ECDSANoncePolicy = .rfc6979
        ) throws -> ECDSA {
            let fields = signFields(
                format: format,
                noncePolicy: noncePolicy,
                privateKey: privateKey,
                payloadLengthField: OpalDiagnostics.Field.publicField(
                    "digest_byte_count",
                    digest.rawRepresentation.count
                )
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaSignBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignBegin),
                fields: fields
            )
            do {
                let signatureModel = try StandardsForEfficientCryptography256k1CurveModel
                    .sign(
                        digestData32Bytes: digest.rawRepresentation,
                        privateKeyData32Bytes: privateKey.rawRepresentation,
                        nonce: noncePolicy.internalECDSANoncePolicy
                    )
                let signature = try ECDSA(signatureModel: signatureModel, format: format)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaSignSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaSignFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        private static func signFields(
            format: ECDSAFormat,
            noncePolicy: ECDSANoncePolicy,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            payloadLengthField: OpalDiagnostics.Field
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("sign"),
                OpalDiagnostics.Field.algorithmField("ecdsa"),
                OpalDiagnostics.Field.formatField(format.diagnosticsName),
                OpalDiagnostics.Field.publicField("nonce_policy", noncePolicy.diagnosticsName),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                payloadLengthField
            ]
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
            let fields = verifyFields(
                payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count),
                verificationKey: verificationKey
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaVerifyBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyBegin),
                fields: fields
            )
            do {
                let result = try OpalCrypto.Signature.verifyValidated(
                    signature: rawRepresentation,
                    message: message,
                    verificationKey: verificationKey,
                    format: format.internalFormat
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: result
                        ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                        : OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: result
                        ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                        : OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
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
            let fields = verifyFields(
                payloadLengthField: OpalDiagnostics.Field.publicField(
                    "digest_byte_count",
                    digest.rawRepresentation.count
                ),
                verificationKey: verificationKey
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaVerifyBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyBegin),
                fields: fields
            )
            do {
                let result = try StandardsForEfficientCryptography256k1CurveModel.verify(
                    signature: signatureModel,
                    digestData32Bytes: digest.rawRepresentation,
                    verificationKeyModel: verificationKey.verificationKeyModel
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: result
                        ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                        : OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: result
                        ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                        : OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch {
                if OpalCrypto.Signature.isInvalidVerificationSignatureError(error) {
                    OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                        event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                        level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                        fields: fields + [OpalDiagnostics.Field.resultField(false)]
                    )
                    return false
                }
                let mappedError = OpalCrypto.Signature.mapCryptographyError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        private func verifyFields(
            payloadLengthField: OpalDiagnostics.Field,
            verificationKey: VerificationKey
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("verify"),
                OpalDiagnostics.Field.algorithmField("ecdsa"),
                OpalDiagnostics.Field.formatField(format.diagnosticsName),
                payloadLengthField,
                OpalDiagnostics.Field.publicField("verification_key_byte_count", verificationKey.rawRepresentation.count),
                OpalDiagnostics.Field.signatureLengthField(rawRepresentation.count)
            ]
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

private extension OpalCrypto.Signature.ECDSAFormat {
    var diagnosticsName: String {
        switch self {
        case .raw:
            return "raw"
        case .der:
            return "der"
        }
    }
}

private extension OpalCrypto.Signature.ECDSANoncePolicy {
    var diagnosticsName: String {
        switch self {
        case .rfc6979:
            return "rfc6979"
        case .random:
            return "random"
        }
    }
}
