// RSABSSAModel~Client.swift

import Foundation
import Security

extension RSABSSAModel {
    internal static func makeBlindRequest(
        message: Data,
        verificationKey: RSABSSAVerificationKeyModel
    ) throws -> BlindRequestMaterial {
        let variant = OpalCrypto.RSABSSA.Variant.sha384PSSRandomized
        let messageRandomizer = try secureRandomBytes(
            count: variant.messageRandomizerByteCount
        )
        let salt = try secureRandomBytes(count: variant.saltByteCount)

        while true {
            let candidateBytes = try secureRandomBytes(
                count: verificationKey.modulusByteCount
            )
            guard let factor = ValidatedBlindingFactor(
                rawRepresentation: candidateBytes,
                modulus: verificationKey.modulus
            ) else {
                continue
            }
            return try makeBlindRequest(
                message: message,
                verificationKey: verificationKey,
                messageRandomizer: messageRandomizer,
                salt: salt,
                makeValidatedFactor: { factor }
            )
        }
    }

    internal static func makeBlindRequest(
        message: Data,
        verificationKey: RSABSSAVerificationKeyModel,
        messageRandomizer: Data,
        salt: Data,
        blindingFactor: Data
    ) throws -> BlindRequestMaterial {
        try makeBlindRequest(
            message: message,
            verificationKey: verificationKey,
            messageRandomizer: messageRandomizer,
            salt: salt,
            makeValidatedFactor: {
                guard let factor = ValidatedBlindingFactor(
                    rawRepresentation: blindingFactor,
                    modulus: verificationKey.modulus
                ) else {
                    throw OpalCrypto.RSABSSA.Error.blindingFailed
                }
                return factor
            }
        )
    }

    private static func makeBlindRequest(
        message: Data,
        verificationKey: RSABSSAVerificationKeyModel,
        messageRandomizer: Data,
        salt: Data,
        makeValidatedFactor: () throws -> ValidatedBlindingFactor
    ) throws -> BlindRequestMaterial {
        let variant = OpalCrypto.RSABSSA.Variant.sha384PSSRandomized
        guard messageRandomizer.count == variant.messageRandomizerByteCount else {
            throw OpalCrypto.RSABSSA.Error.invalidMessageRandomizerLength(
                expected: variant.messageRandomizerByteCount,
                actual: messageRandomizer.count
            )
        }

        var preparedMessage = Data(messageRandomizer)
        preparedMessage.append(message)
        let encodedMessage = try encodePSS(
            message: preparedMessage,
            salt: salt,
            modulusBitCount: verificationKey.modulusBitCount
        )
        let messageRepresentative = RSABSSAInteger(
            bigEndianRepresentation: encodedMessage
        )
        guard messageRepresentative < verificationKey.modulus,
              messageRepresentative.inverseModulo(verificationKey.modulus) != nil else {
            throw OpalCrypto.RSABSSA.Error.invalidMessageRepresentative
        }

        let factor = try makeValidatedFactor()
        guard factor.modulus == verificationKey.modulus,
              let fixedBlindingFactor = factor.value
                .bigEndianRepresentation(
                    paddedTo: verificationKey.modulusByteCount
                ) else {
            throw OpalCrypto.RSABSSA.Error.blindingFailed
        }

        guard let exponentiatedFactor = verificationKey.securityKey.perform({ key in
            var platformError: Unmanaged<CFError>?
            return SecKeyCreateEncryptedData(
                key,
                .rsaEncryptionRaw,
                fixedBlindingFactor as CFData,
                &platformError
            ) as Data?
        }) else {
            throw OpalCrypto.RSABSSA.Error.blindingFailed
        }
        let exponentiatedFactorValue = RSABSSAInteger(
            bigEndianRepresentation: exponentiatedFactor
        )
        guard exponentiatedFactorValue < verificationKey.modulus else {
            throw OpalCrypto.RSABSSA.Error.blindingFailed
        }

        let blindedMessageValue = messageRepresentative.multipliedModulo(
            exponentiatedFactorValue,
            modulus: verificationKey.modulus
        )
        guard let blindedMessage = blindedMessageValue.bigEndianRepresentation(
            paddedTo: verificationKey.modulusByteCount
        ), let blindInverse = factor.inverse.bigEndianRepresentation(
            paddedTo: verificationKey.modulusByteCount
        ) else {
            throw OpalCrypto.RSABSSA.Error.blindingFailed
        }

        return BlindRequestMaterial(
            preparedMessage: preparedMessage,
            messageDigest: OpalCrypto.Hashing.sha256(message),
            messageRandomizer: Data(messageRandomizer),
            salt: Data(salt),
            blindingFactor: Data(factor.rawRepresentation),
            blindedMessage: blindedMessage,
            blindInverse: blindInverse,
            verificationKeyIdentifier: verificationKey.keyIdentifier
        )
    }

    internal static func finalize(
        blindSignature: Data,
        request: BlindRequestMaterial,
        verificationKey: RSABSSAVerificationKeyModel
    ) throws -> Data {
        guard request.verificationKeyIdentifier
            == verificationKey.keyIdentifier else {
            throw OpalCrypto.RSABSSA.Error.verificationKeyMismatch
        }

        let blindSignatureValue = RSABSSAInteger(
            bigEndianRepresentation: blindSignature
        )
        let inverse = RSABSSAInteger(
            bigEndianRepresentation: request.blindInverse
        )
        guard blindSignature.count == verificationKey.modulusByteCount,
              blindSignatureValue < verificationKey.modulus,
              !inverse.isZero,
              inverse < verificationKey.modulus else {
            throw OpalCrypto.RSABSSA.Error.invalidBlindSignature
        }

        let signatureValue = blindSignatureValue.multipliedModulo(
            inverse,
            modulus: verificationKey.modulus
        )
        guard let signature = signatureValue.bigEndianRepresentation(
            paddedTo: verificationKey.modulusByteCount
        ), verify(
            signature: signature,
            preparedMessage: request.preparedMessage,
            verificationKey: verificationKey
        ) else {
            throw OpalCrypto.RSABSSA.Error.invalidBlindSignature
        }
        return signature
    }

    internal static func verify(
        signature: Data,
        preparedMessage: Data,
        verificationKey: RSABSSAVerificationKeyModel
    ) -> Bool {
        guard signature.count == verificationKey.modulusByteCount else {
            return false
        }
        return verificationKey.securityKey.perform { key in
            var platformError: Unmanaged<CFError>?
            return SecKeyVerifySignature(
                key,
                .rsaSignatureMessagePSSSHA384,
                preparedMessage as CFData,
                signature as CFData,
                &platformError
            )
        }
    }

    private static func secureRandomBytes(count: Int) throws -> Data {
        do {
            return try OpalCrypto.SecureRandom.makeBytes(count: count)
        } catch {
            throw OpalCrypto.RSABSSA.Error.randomGenerationFailed
        }
    }

    private struct ValidatedBlindingFactor {
        let rawRepresentation: Data
        let value: RSABSSAInteger
        let modulus: RSABSSAInteger
        let inverse: RSABSSAInteger

        init?(rawRepresentation: Data, modulus: RSABSSAInteger) {
            let value = RSABSSAInteger(
                bigEndianRepresentation: rawRepresentation
            )
            guard !value.isZero,
                  value < modulus,
                  let inverse = value.inverseModulo(modulus) else {
                return nil
            }
            self.rawRepresentation = Data(rawRepresentation)
            self.value = value
            self.modulus = modulus
            self.inverse = inverse
        }
    }
}
