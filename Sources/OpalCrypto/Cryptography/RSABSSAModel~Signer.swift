// RSABSSAModel~Signer.swift

import Foundation
import Security

extension RSABSSAModel {
    internal static func blindSign(
        blindedMessage: Data,
        signingKey: RSABSSASigningKeyModel
    ) throws -> Data {
        let verificationKey = signingKey.verificationKey
        let messageRepresentative = RSABSSAInteger(
            bigEndianRepresentation: blindedMessage
        )
        guard blindedMessage.count == verificationKey.modulusByteCount,
              messageRepresentative < verificationKey.modulus else {
            throw OpalCrypto.RSABSSA.Error.messageRepresentativeOutOfRange
        }

        // RFC 9474 BlindSign is the raw RSA private operation over a blinded,
        // already encoded representative. Security's raw encryption primitive
        // exposes that exact operation without imposing signature formatting.
        guard let signature = signingKey.securityKey.perform({ key in
            var platformError: Unmanaged<CFError>?
            return SecKeyCreateDecryptedData(
                key,
                .rsaEncryptionRaw,
                blindedMessage as CFData,
                &platformError
            ) as Data?
        }), signature.count == verificationKey.modulusByteCount else {
            throw OpalCrypto.RSABSSA.Error.signingFailed
        }

        guard let recoveredMessage = verificationKey.securityKey.perform({ key in
            var platformError: Unmanaged<CFError>?
            return SecKeyCreateEncryptedData(
                key,
                .rsaEncryptionRaw,
                signature as CFData,
                &platformError
            ) as Data?
        }), recoveredMessage.count == verificationKey.modulusByteCount,
            recoveredMessage == blindedMessage else {
            throw OpalCrypto.RSABSSA.Error.signingFailed
        }
        return signature
    }
}
