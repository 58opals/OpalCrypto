// OpalCrypto.Signature+Schnorr.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature {
    public struct Schnorr: Sendable, Equatable {
        internal let signatureModel: SchnorrSignatureModel.Signature

        public var rawRepresentation: Data {
            signatureModel.raw64ByteSignatureData
        }

        public init(rawRepresentation: Data) throws {
            do {
                signatureModel = try SchnorrSignatureModel.Signature(
                    raw64ByteSignatureData: rawRepresentation
                )
                _ = try FieldElementModel(data32: signatureModel.r)
                _ = try ScalarModel(data32: signatureModel.s, requireNonZero: false)
            } catch SchnorrSignatureModel.Error.invalidSignatureLength(let actual) {
                throw Error.invalidSignatureLength(expected: 64, actual: actual)
            } catch {
                throw Error.invalidSignature
            }
        }

        internal init(signatureModel: SchnorrSignatureModel.Signature) {
            self.signatureModel = signatureModel
        }

        public static func sign(
            digest: Digest,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            noncePolicy: SchnorrNoncePolicy = .bip340Deterministic
        ) throws -> Schnorr {
            let fields = signFields(
                digest: digest,
                privateKeyByteCount: privateKey.rawRepresentation.count,
                noncePolicy: noncePolicy
            )
            Self.recordSchnorr(
                event: OpalDiagnostics.Event.schnorrSignBegin,
                fields: fields
            )
            do {
                let signatureData = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: digest.rawRepresentation,
                    with: privateKey.rawRepresentation,
                    in: .schnorr,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
                let signature = try Schnorr(rawRepresentation: signatureData)
                Self.recordSchnorr(
                    event: OpalDiagnostics.Event.schnorrSignSucceeded,
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                Self.recordSchnorrFailed(
                    event: OpalDiagnostics.Event.schnorrSignFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
        }

        internal static func sign(
            digest: Digest,
            parsedPrivateKeyModel: ParsedPrivateKeyModel,
            noncePolicy: SchnorrNoncePolicy = .bip340Deterministic
        ) throws -> Schnorr {
            let fields = signFields(
                digest: digest,
                privateKeyByteCount: OpalCrypto.Secp256k1.SigningKey.privateKeyByteCount,
                noncePolicy: noncePolicy
            )
            Self.recordSchnorr(
                event: OpalDiagnostics.Event.schnorrSignBegin,
                fields: fields
            )
            do {
                let signatureModel = try SchnorrSignatureModel.sign(
                    digestData32Bytes: digest.rawRepresentation,
                    parsedPrivateKeyModel: parsedPrivateKeyModel,
                    nonce: noncePolicy.internalNoncePolicy
                )
                let signature = Schnorr(signatureModel: signatureModel)
                Self.recordSchnorr(
                    event: OpalDiagnostics.Event.schnorrSignSucceeded,
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                Self.recordSchnorrFailed(
                    event: OpalDiagnostics.Event.schnorrSignFailed,
                    error: mappedError,
                    fields: fields
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
            let fields = [
                OpalDiagnostics.Field.operationField("verify"),
                OpalDiagnostics.Field.algorithmField("schnorr"),
                OpalDiagnostics.Field.formatField("bip340"),
                OpalDiagnostics.Field.publicField("digest_byte_count", digest.rawRepresentation.count),
                OpalDiagnostics.Field.publicField(
                    "verification_key_byte_count",
                    verificationKey.verificationKeyModel.compressedPublicKeyData.count
                ),
                OpalDiagnostics.Field.signatureLengthField(rawRepresentation.count)
            ]
            Self.recordSchnorr(
                event: OpalDiagnostics.Event.schnorrVerifyBegin,
                fields: fields
            )
            do {
                let result = try SchnorrSignatureModel.verify(
                    signature: signatureModel,
                    digestData32Bytes: digest.rawRepresentation,
                    verificationKeyModel: verificationKey.verificationKeyModel
                )
                Self.recordSchnorr(
                    event: result
                        ? OpalDiagnostics.Event.schnorrVerifySucceeded
                        : OpalDiagnostics.Event.schnorrVerifyFailed,
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                Self.recordSchnorrFailed(
                    event: OpalDiagnostics.Event.schnorrVerifyFailed,
                    error: mappedError,
                    fields: fields
                )
                throw mappedError
            }
        }

        private static func signFields(
            digest: Digest,
            privateKeyByteCount: Int,
            noncePolicy: SchnorrNoncePolicy
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("sign"),
                OpalDiagnostics.Field.algorithmField("schnorr"),
                OpalDiagnostics.Field.formatField("bip340"),
                OpalDiagnostics.Field.publicField("nonce_policy", noncePolicy.diagnosticsName),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKeyByteCount),
                OpalDiagnostics.Field.publicField("digest_byte_count", digest.rawRepresentation.count)
            ]
        }

        private static func recordSchnorr(
            event: OpalDiagnostics.Event,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: event,
                level: .opalCryptoDefault(for: event),
                fields: fields
            )
        }

        private static func recordSchnorrFailed(
            event: OpalDiagnostics.Event,
            error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            recordSchnorr(
                event: event,
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
