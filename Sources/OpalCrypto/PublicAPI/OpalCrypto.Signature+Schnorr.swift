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
            let fields = [
                OpalDiagnostics.Field.operationField("sign"),
                OpalDiagnostics.Field.algorithmField("schnorr"),
                OpalDiagnostics.Field.publicField("nonce_policy", noncePolicy.diagnosticsName),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("digest_byte_count", digest.rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.schnorrSignBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.schnorrSignBegin),
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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.schnorrSignSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.schnorrSignSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.schnorrSignFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.schnorrSignFailed),
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
            let fields = [
                OpalDiagnostics.Field.operationField("verify"),
                OpalDiagnostics.Field.algorithmField("schnorr"),
                OpalDiagnostics.Field.publicField("digest_byte_count", digest.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("verification_key_byte_count", verificationKey.rawRepresentation.count),
                OpalDiagnostics.Field.signatureLengthField(rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.schnorrVerifyBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.schnorrVerifyBegin),
                fields: fields
            )
            do {
                let result = try OpalCrypto.Signature.verifyValidated(
                    signature: rawRepresentation,
                    message: digest.rawRepresentation,
                    verificationKey: verificationKey,
                    format: .schnorr
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: result
                        ? OpalDiagnostics.Event.schnorrVerifySucceeded
                        : OpalDiagnostics.Event.schnorrVerifyFailed,
                    level: .opalCryptoDefault(for: result
                        ? OpalDiagnostics.Event.schnorrVerifySucceeded
                        : OpalDiagnostics.Event.schnorrVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.schnorrVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.schnorrVerifyFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}

private extension OpalCrypto.Signature.SchnorrNoncePolicy {
    var diagnosticsName: String {
        switch self {
        case .bip340Deterministic:
            return "bip340_deterministic"
        case .random:
            return "random"
        }
    }
}
