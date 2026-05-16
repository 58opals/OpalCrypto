// OpalCrypto.BlindSignature+Request.swift

import Foundation

extension OpalCrypto.BlindSignature {
        public struct Request: Sendable {
        internal let requestState: BlindSignatureModel.RequestState

        public var scalar: OpalCrypto.Secp256k1.Scalar {
            OpalCrypto.Secp256k1.Scalar(scalarModel: requestState.requestScalar)
        }

        public init(
            signerPublicKey: OpalCrypto.Secp256k1.PublicKey,
            noncePoint: OpalCrypto.Secp256k1.PublicKey,
            messageDigest: OpalCrypto.Signature.Digest
        ) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("request"),
                OpalCryptoDiagnostics.publicField("signer_public_key_byte_count", signerPublicKey.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("nonce_point_byte_count", noncePoint.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("digest_byte_count", messageDigest.rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.blindSignatureRequestBegin,
                category: OpalCryptoDiagnostics.Category.blindSignature,
                fields: fields
            )
            do {
                requestState = try BlindSignatureModel.RequestState(
                    signerPublicKey: signerPublicKey.rawRepresentation,
                    noncePoint: noncePoint.rawRepresentation,
                    messageDigest32Bytes: messageDigest.rawRepresentation
                )
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureRequestFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.blindSignatureRequestSucceeded,
                category: OpalCryptoDiagnostics.Category.blindSignature,
                fields: fields
            )
        }

        public func finalize(
            responseScalar: OpalCrypto.Secp256k1.Scalar,
            verify: Bool = true
        ) throws -> OpalCrypto.Signature.Schnorr {
            let fields = [
                OpalCryptoDiagnostics.operationField("unblind"),
                OpalCryptoDiagnostics.publicField("response_scalar_byte_count", responseScalar.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("verify", verify)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.blindSignatureUnblindBegin,
                category: OpalCryptoDiagnostics.Category.blindSignature,
                fields: fields
            )
            do {
                let signature = try requestState.finalize(
                    responseScalarData32Bytes: responseScalar.rawRepresentation,
                    verify: verify
                )
                let parsedSignature = try OpalCrypto.Signature.Schnorr(rawRepresentation: signature)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureUnblindSucceeded,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + [
                        OpalCryptoDiagnostics.signatureLengthField(parsedSignature.rawRepresentation.count)
                    ]
                )
                if verify {
                    OpalCryptoDiagnostics.record(
                        OpalCryptoDiagnostics.Event.blindSignatureVerifySucceeded,
                        category: OpalCryptoDiagnostics.Category.blindSignature,
                        fields: fields + [OpalCryptoDiagnostics.resultField(true)]
                    )
                }
                return parsedSignature
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                if verify, mappedError == .verificationFailed {
                    OpalCryptoDiagnostics.record(
                        OpalCryptoDiagnostics.Event.blindSignatureVerifyFailed,
                        category: OpalCryptoDiagnostics.Category.blindSignature,
                        fields: fields + [OpalCryptoDiagnostics.resultField(false)]
                    )
                }
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureUnblindFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Signature.Error {
                let mappedError = OpalCrypto.BlindSignature.Error.verificationFailed
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureUnblindFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw mappedError
            }
        }
    }
}
