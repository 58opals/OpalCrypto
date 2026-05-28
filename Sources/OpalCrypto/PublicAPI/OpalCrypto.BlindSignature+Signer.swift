// OpalCrypto.BlindSignature+Signer.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.BlindSignature {
    public actor Signer {
        internal var signerState: BlindSignatureModel.SignerState

        public nonisolated let noncePoint: OpalCrypto.Secp256k1.PublicKey

        public init() throws {
            let fields = [
                OpalDiagnostics.Field.operationField("signer_prepare")
            ]
            do {
                let signerState = try BlindSignatureModel.SignerState()
                self.signerState = signerState
                self.noncePoint = try OpalCrypto.Secp256k1.PublicKey(
                    validatingRawRepresentation: signerState.noncePointData
                )
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureSignerPrepareFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignerPrepareFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = OpalCrypto.BlindSignature.mapSecp256k1Error(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureSignerPrepareFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignerPrepareFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                event: OpalDiagnostics.Event.blindSignatureSignerPrepareSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignerPrepareSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("nonce_point_byte_count", noncePoint.rawRepresentation.count)
                ]
            )
        }

        public func sign(
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            requestScalar: OpalCrypto.Secp256k1.Scalar
        ) async throws -> OpalCrypto.Secp256k1.Scalar {
            let fields = [
                OpalDiagnostics.Field.operationField("sign"),
                OpalDiagnostics.Field.publicField("private_key_byte_count", privateKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("request_scalar_byte_count", requestScalar.rawRepresentation.count)
            ]
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                event: OpalDiagnostics.Event.blindSignatureSignBegin,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignBegin),
                fields: fields
            )
            do {
                let responseScalar = try signerState.sign(
                    privateKey: privateKey.rawRepresentation,
                    requestScalarData32Bytes: requestScalar.rawRepresentation
                )
                let scalar = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: responseScalar)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureSignSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(scalar.rawRepresentation.count)
                    ]
                )
                return scalar
            } catch let error as BlindSignatureModel.Error {
                let mappedError = OpalCrypto.BlindSignature.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureSignFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = OpalCrypto.BlindSignature.mapSecp256k1Error(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.blindSignature).record(
                    event: OpalDiagnostics.Event.blindSignatureSignFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.blindSignatureSignFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}
