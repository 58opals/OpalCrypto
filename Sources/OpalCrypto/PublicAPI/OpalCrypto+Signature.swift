// OpalCrypto+Signature.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Signature {
        public static func deriveVerificationKey(
            from privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> VerificationKey {
            let fields = [
                OpalDiagnostics.Field.operationField("verification_key_derive"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.inputLengthField(privateKey.rawRepresentation.count),
                OpalDiagnostics.Field.publicField(
                    "private_key_byte_count",
                    privateKey.rawRepresentation.count
                )
            ]
            do {
                let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                    .Operation.makeVerificationKey(
                        fromPrivateKeyData32Bytes: privateKey.rawRepresentation
                    )
                let verificationKey = VerificationKey(verificationKeyModel: verificationKeyModel)
                recordVerificationKeyDeriveSucceeded(
                    verificationKey: verificationKey,
                    fields: fields
                )
                return verificationKey
            } catch {
                let mappedError = mapCryptographyError(error)
                recordVerificationKeyDeriveFailed(mappedError, fields: fields)
                throw mappedError
            }
        }

        private static func recordVerificationKeyDeriveSucceeded(
            verificationKey: VerificationKey,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.verificationKeyDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(verificationKey.rawRepresentation.count),
                    OpalDiagnostics.Field.publicField(
                        "verification_key_byte_count",
                        verificationKey.rawRepresentation.count
                    )
                ]
            )
        }

        private static func recordVerificationKeyDeriveFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.verificationKeyDeriveFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyDeriveFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
