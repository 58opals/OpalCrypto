// OpalCrypto+Signature.swift

import Foundation

extension OpalCrypto {
    public enum Signature {
        public static func deriveVerificationKey(
            from privateKey: OpalCrypto.Secp256k1.PrivateKey
        ) throws -> VerificationKey {
            do {
                let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                    .Operation.makeVerificationKey(
                        fromPrivateKeyData32Bytes: privateKey.rawRepresentation
                    )
                return VerificationKey(verificationKeyModel: verificationKeyModel)
            } catch {
                throw mapCryptographyError(error)
            }
        }
    }
}
