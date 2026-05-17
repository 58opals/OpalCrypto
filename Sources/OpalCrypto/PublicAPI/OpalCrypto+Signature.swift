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
                OpalDiagnostics.Field.inputLengthField(privateKey.rawRepresentation.count)
            ]
            do {
                let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                    .Operation.makeVerificationKey(
                        fromPrivateKeyData32Bytes: privateKey.rawRepresentation
                    )
                let verificationKey = VerificationKey(verificationKeyModel: verificationKeyModel)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.verificationKeyDeriveSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyDeriveSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(verificationKey.rawRepresentation.count)
                    ]
                )
                return verificationKey
            } catch {
                let mappedError = mapCryptographyError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.verificationKeyDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}
