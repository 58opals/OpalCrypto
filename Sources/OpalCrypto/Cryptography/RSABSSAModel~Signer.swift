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

        guard let signature = signingKey.securityKey.perform({ key in
            var platformError: Unmanaged<CFError>?
            return SecKeyCreateSignature(
                key,
                .rsaSignatureRaw,
                blindedMessage as CFData,
                &platformError
            ) as Data?
        }), signature.count == verificationKey.modulusByteCount else {
            throw OpalCrypto.RSABSSA.Error.signingFailed
        }

        guard verificationKey.securityKey.perform({ key in
            var platformError: Unmanaged<CFError>?
            return SecKeyVerifySignature(
                key,
                .rsaSignatureRaw,
                blindedMessage as CFData,
                signature as CFData,
                &platformError
            )
        }) else {
            throw OpalCrypto.RSABSSA.Error.signingFailed
        }
        return signature
    }
}
