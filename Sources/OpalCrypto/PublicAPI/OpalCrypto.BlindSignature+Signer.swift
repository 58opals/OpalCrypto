// OpalCrypto.BlindSignature+Signer.swift

import Foundation

extension OpalCrypto.BlindSignature {
    public actor Signer {
        internal var signerState: BlindSignatureModel.SignerState

        public nonisolated let noncePoint: OpalCrypto.Secp256k1.PublicKey

        public init() throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("signer_prepare")
            ]
            do {
                let signerState = try BlindSignatureModel.SignerState()
                self.signerState = signerState
                self.noncePoint = try OpalCrypto.Secp256k1.PublicKey(
                    rawRepresentation: signerState.noncePointData
                )
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureSignerPrepareFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = OpalCrypto.BlindSignature.mapSecp256k1Error(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureSignerPrepareFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.blindSignatureSignerPrepareSucceeded,
                category: OpalCryptoDiagnostics.Category.blindSignature,
                fields: fields + [
                    OpalCryptoDiagnostics.publicField("nonce_point_byte_count", noncePoint.rawRepresentation.count)
                ]
            )
        }

        public func sign(
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            requestScalar: OpalCrypto.Secp256k1.Scalar
        ) async throws -> OpalCrypto.Secp256k1.Scalar {
            let fields = [
                OpalCryptoDiagnostics.operationField("sign"),
                OpalCryptoDiagnostics.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("request_scalar_byte_count", requestScalar.rawRepresentation.count)
            ]
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.blindSignatureSignBegin,
                category: OpalCryptoDiagnostics.Category.blindSignature,
                fields: fields
            )
            do {
                let responseScalar = try signerState.sign(
                    privateKey: privateKey.rawRepresentation,
                    requestScalarData32Bytes: requestScalar.rawRepresentation
                )
                let scalar = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: responseScalar)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureSignSucceeded,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(scalar.rawRepresentation.count)
                    ]
                )
                return scalar
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureSignFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = OpalCrypto.BlindSignature.mapSecp256k1Error(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.blindSignatureSignFailed,
                    category: OpalCryptoDiagnostics.Category.blindSignature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}
