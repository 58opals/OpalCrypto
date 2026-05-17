// OpalCrypto.BlindSignature+Request.swift

import Foundation
import OpalDiagnostics

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
                OpalDiagnostics.Field.operationField("request"),
                OpalDiagnostics.Field.publicField("signer_public_key_byte_count", signerPublicKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("nonce_point_byte_count", noncePoint.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("digest_byte_count", messageDigest.rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                event: OpalDiagnostics.Event.blindSignatureRequestBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureRequestBegin),
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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureRequestFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureRequestFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                event: OpalDiagnostics.Event.blindSignatureRequestSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureRequestSucceeded),
                fields: fields
            )
        }

        public func finalize(
            responseScalar: OpalCrypto.Secp256k1.Scalar,
            verify: Bool = true
        ) throws -> OpalCrypto.Signature.Schnorr {
            let fields = [
                OpalDiagnostics.Field.operationField("unblind"),
                OpalDiagnostics.Field.publicField("response_scalar_byte_count", responseScalar.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("verify", verify)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                event: OpalDiagnostics.Event.blindSignatureUnblindBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureUnblindBegin),
                fields: fields
            )
            do {
                let signature = try requestState.finalize(
                    responseScalarData32Bytes: responseScalar.rawRepresentation,
                    verify: verify
                )
                let parsedSignature = try OpalCrypto.Signature.Schnorr(rawRepresentation: signature)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureUnblindSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureUnblindSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.signatureLengthField(parsedSignature.rawRepresentation.count)
                    ]
                )
                if verify {
                    OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                        event: OpalDiagnostics.Event.blindSignatureVerifySucceeded,
                        level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureVerifySucceeded),
                        fields: fields + [OpalDiagnostics.Field.resultField(true)]
                    )
                }
                return parsedSignature
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                if verify, mappedError == .verificationFailed {
                    OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                        event: OpalDiagnostics.Event.blindSignatureVerifyFailed,
                        level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureVerifyFailed),
                        fields: fields + [OpalDiagnostics.Field.resultField(false)]
                    )
                }
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureUnblindFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureUnblindFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch is OpalCrypto.Signature.Error {
                let mappedError = OpalCrypto.BlindSignature.Error.verificationFailed
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureUnblindFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureUnblindFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}
