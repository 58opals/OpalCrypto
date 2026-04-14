// CommunicationBoxModel.swift

import CommonCrypto
import Foundation

enum CommunicationBoxModel {

    static func encrypt(
        message: Data,
        recipientPublicKey: Data,
        paddedPlaintextLength: Int?
    ) throws -> Data {
        try validateCompressedPublicKey(recipientPublicKey)

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
            paddedPlaintextLength: paddedPlaintextLength
        )
        let ciphertext = try crypt(
            plaintext,
            key: symmetricKey,
            operation: CCOperation(kCCEncrypt)
        )
        let authenticationCode = Data(
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(ciphertext, key: symmetricKey)
                .prefix(16)
        )
        return ephemeralPublicKey + ciphertext + authenticationCode
    }

    static func decrypt(
        _ ciphertext: Data,
        privateKey: Data
    ) throws -> DecryptionResult {
        guard ciphertext.count >= minimumCiphertextLength else {
            throw Error.invalidCiphertext
        }
        let ephemeralPublicKey = Data(ciphertext.prefix(33))
        let symmetricKey = try deriveSharedSecret(
            privateKey: privateKey,
            publicKey: ephemeralPublicKey
        )
        let message = try decrypt(ciphertext, symmetricKey: symmetricKey)
        return DecryptionResult(message: message, symmetricKey: symmetricKey)
    }

    static func decrypt(
        _ ciphertext: Data,
        symmetricKey: Data
    ) throws -> Data {
        guard symmetricKey.count == 32 else {
            throw Error.invalidSymmetricKeyLength(actual: symmetricKey.count)
        }
        guard ciphertext.count >= minimumCiphertextLength else {
            throw Error.invalidCiphertext
        }

        let encryptedPayload = ciphertext.dropFirst(33).dropLast(16)
        guard !encryptedPayload.isEmpty, encryptedPayload.count.isMultiple(of: 16) else {
            throw Error.invalidCiphertext
        }

        let expectedAuthenticationCode = Data(
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(Data(encryptedPayload), key: symmetricKey)
                .prefix(16)
        )
        let actualAuthenticationCode = Data(ciphertext.suffix(16))
        guard expectedAuthenticationCode == actualAuthenticationCode else {
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
        guard messageLength >= 0, 4 + messageLength <= plaintext.count else {
            throw Error.invalidCiphertext
        }
        return plaintext.dataSlice(in: 4..<(4 + messageLength))
    }

    private static var minimumCiphertextLength: Int {
        33 + 16 + 16
    }

    private static func validateCompressedPublicKey(_ publicKey: Data) throws {
        guard publicKey.count == 33 else {
            throw Error.invalidPublicKeyLength(actual: publicKey.count)
        }
        guard let prefix = publicKey.first else {
            throw Error.invalidPublicKeyLength(actual: publicKey.count)
        }
        guard prefix == 0x02 || prefix == 0x03 else {
            throw Error.invalidPublicKeyPrefix(actual: prefix)
        }
    }

    private static func deriveSharedSecret(
        privateKey: Data,
        publicKey: Data
    ) throws -> Data {
        try validateCompressedPublicKey(publicKey)
        do {
            return try StandardsForEfficientCryptography256k1CurveModel.Operation
                .deriveSharedSecret(
                    privateKeyData32Bytes: privateKey,
                    publicKey: publicKey
                )
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyLength(let actual) {
            throw Error.invalidPrivateKeyLength(actual: actual)
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyValue {
            throw Error.invalidPrivateKey
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPublicKeyLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPublicKeyValue {
            throw Error.invalidPublicKey
        } catch {
            throw Error.cryptographyFailure
        }
    }

    private static func makePlaintext(
        message: Data,
        paddedPlaintextLength: Int?
    ) throws -> Data {
        let minimumLength = message.count + 4
        let resolvedLength: Int
        if let paddedPlaintextLength {
            guard paddedPlaintextLength.isMultiple(of: 16) else {
                throw Error.paddedPlaintextLengthNotMultipleOf16(actual: paddedPlaintextLength)
            }
            guard paddedPlaintextLength >= minimumLength else {
                throw Error.invalidPaddedPlaintextLength(
                    minimum: minimumLength,
                    actual: paddedPlaintextLength
                )
            }
            resolvedLength = paddedPlaintextLength
        } else {
            resolvedLength = ((minimumLength + 15) / 16) * 16
        }

        var plaintext = Data()
        plaintext.reserveCapacity(resolvedLength)
        plaintext.appendUInt32BigEndian(UInt32(message.count))
        plaintext.append(message)
        if resolvedLength > plaintext.count {
            plaintext.append(
                Data(repeating: 0x00, count: resolvedLength - plaintext.count)
            )
        }
        return plaintext
    }

    private static func crypt(
        _ input: Data,
        key: Data,
        operation: CCOperation
    ) throws -> Data {
        guard key.count == kCCKeySizeAES256 else {
            throw Error.invalidSymmetricKeyLength(actual: key.count)
        }
        guard input.count.isMultiple(of: kCCBlockSizeAES128) else {
            throw Error.invalidCiphertext
        }

        let initializationVector = Data(repeating: 0x00, count: kCCBlockSizeAES128)
        var output = Data(repeating: 0x00, count: input.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputLength = 0

        let status = output.withUnsafeMutableBytes { outputBuffer in
            input.withUnsafeBytes { inputBuffer in
                key.withUnsafeBytes { keyBuffer in
                    initializationVector.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBuffer.baseAddress,
                            key.count,
                            ivBuffer.baseAddress,
                            inputBuffer.baseAddress,
                            input.count,
                            outputBuffer.baseAddress,
                            outputCapacity,
                            &outputLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw Error.cryptographyFailure
        }
        output.removeSubrange(outputLength..<output.count)
        return output
    }
}
