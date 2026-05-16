// OpalCrypto+Signature.swift

import Foundation

extension OpalCrypto {
    public enum Signature {
        public static func deriveVerificationKey(
            from privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> VerificationKey {
            let fields = [
                OpalCryptoDiagnostics.operationField("verification_key_derive"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.inputLengthField(privateKey.rawRepresentation.count)
            ]
            do {
                let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                    .Operation.makeVerificationKey(
                        fromPrivateKeyData32Bytes: privateKey.rawRepresentation
                    )
                let verificationKey = VerificationKey(verificationKeyModel: verificationKeyModel)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyDeriveSucceeded,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(verificationKey.rawRepresentation.count)
                    ]
                )
                return verificationKey
            } catch {
                let mappedError = mapCryptographyError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyDeriveFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }
    }
}
