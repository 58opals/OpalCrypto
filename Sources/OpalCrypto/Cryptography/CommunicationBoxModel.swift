// CommunicationBoxModel.swift

import CommonCrypto
import Foundation

enum CommunicationBoxModel {
    static func encrypt(
        message: Data,
        recipientPublicKey: Data,
        paddedPlaintextLength: Int?,
        maximumCiphertextByteCount: Int
    ) throws -> Data {
        let byteCounts = try preflightCiphertextByteCount(
            messageByteCount: message.count,
            paddedPlaintextLength: paddedPlaintextLength,
            maximumCiphertextByteCount: maximumCiphertextByteCount
        )
        try validateSecp256k1PublicKey(recipientPublicKey)

        let ephemeralPrivateKey: Data
        do {
            ephemeralPrivateKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .generatePrivateKeyData32Bytes()
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.randomGenerationFailed {
            throw Error.cryptographyFailure
        } catch {
            throw Error.invalidPrivateKey
        }

        let ephemeralPublicKey: Data
        do {
            ephemeralPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKey(
                    fromPrivateKeyData32Bytes: ephemeralPrivateKey,
                    format: .compressed
                )
        } catch {
            throw Error.cryptographyFailure
        }

        let symmetricKey = try deriveSharedSecret(
            privateKey: ephemeralPrivateKey,
            publicKey: recipientPublicKey
        )
        let plaintext = try makePlaintext(
            message: message,
            resolvedPlaintextLength: byteCounts.plaintextByteCount
        )
        var envelope = try crypt(
            plaintext,
            key: symmetricKey,
            operation: CCOperation(kCCEncrypt)
        )
        envelope.reserveCapacity(byteCounts.ciphertextByteCount)
        envelope.insert(contentsOf: ephemeralPublicKey, at: envelope.startIndex)
        let authenticationCode = Data(
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(envelope, key: symmetricKey)
                .prefix(16)
        )
        envelope.append(authenticationCode)
        return envelope
    }
    static func decrypt(
        _ ciphertext: Data,
        privateKey: Data,
        maximumCiphertextByteCount: Int
    ) throws -> DecryptionResult {
        try validateCiphertextEnvelope(
            ciphertext,
            maximumCiphertextByteCount: maximumCiphertextByteCount
        )
        try validatePrivateKey(privateKey)
        let ephemeralPublicKey = Data(ciphertext.prefix(33))
        let symmetricKey: Data
        do {
            symmetricKey = try deriveSharedSecret(
                privateKey: privateKey,
                publicKey: ephemeralPublicKey
            )
        } catch Error.invalidPublicKeyLength,
                Error.invalidPublicKeyPrefix,
                Error.invalidPublicKey {
            throw Error.invalidCiphertext
        }
        let message = try decryptValidatedCiphertext(ciphertext, symmetricKey: symmetricKey)
        return DecryptionResult(message: message, symmetricKey: symmetricKey)
    }

    static func decrypt(
        _ ciphertext: Data,
        symmetricKey: Data,
        maximumCiphertextByteCount: Int
    ) throws -> Data {
        try validateCiphertextEnvelope(
            ciphertext,
            maximumCiphertextByteCount: maximumCiphertextByteCount
        )
        guard symmetricKey.count == 32 else {
            throw Error.invalidSymmetricKeyLength(actual: symmetricKey.count)
        }

        return try decryptValidatedCiphertext(ciphertext, symmetricKey: symmetricKey)
    }

    private static func decryptValidatedCiphertext(
        _ ciphertext: Data,
        symmetricKey: Data
    ) throws -> Data {
        let encryptedPayload = ciphertext.dropFirst(33).dropLast(16)
        let expectedAuthenticationCode = Data(
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(ciphertext.dropLast(16), key: symmetricKey)
                .prefix(16)
        )
        let actualAuthenticationCode = Data(ciphertext.suffix(16))
        guard expectedAuthenticationCode.constantTimeEquals(actualAuthenticationCode) else {
            throw Error.invalidCiphertext
        }

        let plaintext = try crypt(
            Data(encryptedPayload),
            key: symmetricKey,
            operation: CCOperation(kCCDecrypt)
        )
        guard plaintext.count >= 4 else {
            throw Error.invalidCiphertext
        }

        let messageLength = Int(plaintext.uint32BigEndian(at: 0))
        guard 4 + messageLength <= plaintext.count else {
            throw Error.invalidCiphertext
        }
        guard plaintext[(4 + messageLength)..<plaintext.endIndex].allSatisfy({ $0 == 0 }) else {
            throw Error.invalidCiphertext
        }
        return plaintext.dataSlice(in: 4..<(4 + messageLength))
    }
}
