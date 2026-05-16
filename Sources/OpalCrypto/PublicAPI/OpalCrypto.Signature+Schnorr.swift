// OpalCrypto.Signature+Schnorr.swift

import Foundation

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
                OpalCryptoDiagnostics.operationField("sign"),
                OpalCryptoDiagnostics.algorithmField("schnorr"),
                OpalCryptoDiagnostics.publicField("nonce_policy", noncePolicy.diagnosticsName),
                OpalCryptoDiagnostics.publicField("digest_byte_count", digest.rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.schnorrSignBegin,
                category: OpalCryptoDiagnostics.Category.signature,
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
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.schnorrSignSucceeded,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + [
                        OpalCryptoDiagnostics.signatureLengthField(signature.rawRepresentation.count)
                    ]
                )
                return signature
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.schnorrSignFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
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
                OpalCryptoDiagnostics.operationField("verify"),
                OpalCryptoDiagnostics.algorithmField("schnorr"),
                OpalCryptoDiagnostics.publicField("digest_byte_count", digest.rawRepresentation.count),
                OpalCryptoDiagnostics.signatureLengthField(rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.schnorrVerifyBegin,
                category: OpalCryptoDiagnostics.Category.signature,
                fields: fields
            )
            do {
                let result = try OpalCrypto.Signature.verifyValidated(
                    signature: rawRepresentation,
                    message: digest.rawRepresentation,
                    verificationKey: verificationKey,
                    format: .schnorr
                )
                OpalCryptoDiagnostics.record(
                    result
                        ? OpalCryptoDiagnostics.Event.schnorrVerifySucceeded
                        : OpalCryptoDiagnostics.Event.schnorrVerifyFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + [OpalCryptoDiagnostics.resultField(result)]
                )
                return result
            } catch {
                let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.schnorrVerifyFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
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
