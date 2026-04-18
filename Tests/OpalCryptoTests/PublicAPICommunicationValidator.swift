// PublicAPICommunicationValidator.swift

import CommonCrypto
import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication validation")
struct PublicAPICommunicationValidator {
    @Test("Secp256k1 shared secrets are symmetric")
    func secp256k1SharedSecretsAreSymmetric() throws {
        let privateKeyA = try OpalCrypto.Secp256k1.generatePrivateKey()
        let publicKeyA = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKeyA
        )
        let privateKeyB = try OpalCrypto.Secp256k1.generatePrivateKey()
        let publicKeyB = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKeyB
        )

        let sharedSecretAB = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyA,
            publicKey: publicKeyB
        )
        let sharedSecretBA = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyB,
            publicKey: publicKeyA
        )

        #expect(sharedSecretAB == sharedSecretBA)
        #expect(sharedSecretAB.count == 32)
    }

    @Test("Communication boxes round-trip through private and symmetric decryption")
    func communicationBoxesRoundTripThroughPrivateAndSymmetricDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        let message = Data("cashfusion-proof".utf8)

        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: recipientPublicKey,
            paddedPlaintextLength: 32
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey
        )

        #expect(decrypted.message == message)
        #expect(
            try OpalCrypto.Communication.decrypt(
                ciphertext,
                symmetricKey: decrypted.symmetricKey
            ) == message
        )
        #expect(
            try OpalCrypto.Communication.encrypt(
                message: Data(),
                recipientPublicKey: recipientPublicKey
            ).count == 65
        )
    }

    @Test("Communication encryption accepts uncompressed recipient public keys")
    func communicationEncryptionAcceptsUncompressedRecipientPublicKeys() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let uncompressedRecipientPublicKey = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.derivePublicKey(
                fromPrivateKeyData32Bytes: recipientPrivateKey,
                format: .uncompressed
            )
        let message = Data("recipient-uncompressed".utf8)

        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: uncompressedRecipientPublicKey,
            paddedPlaintextLength: 32
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey
        )

        #expect(decrypted.message == message)
    }

    @Test("Communication encryption reports the uncompressed expected length for short SEC1 recipient keys")
    func communicationEncryptionReportsTheUncompressedExpectedLengthForShortSec1RecipientKeys() {
        let truncatedUncompressedRecipientPublicKey = Data(
            [0x04] + Array(repeating: 0x11, count: 63)
        )

        do {
            _ = try OpalCrypto.Communication.encrypt(
                message: Data("recipient-short-key".utf8),
                recipientPublicKey: truncatedUncompressedRecipientPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication boxes reject tampered authentication codes")
    func communicationBoxesRejectTamperedAuthenticationCodes() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        var ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("proof".utf8),
            recipientPublicKey: recipientPublicKey
        )
        ciphertext[ciphertext.index(before: ciphertext.endIndex)] ^= 0x01

        do {
            _ = try OpalCrypto.Communication.decrypt(
                ciphertext,
                privateKey: recipientPrivateKey
            )
            Issue.record("Expected invalid ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication box private-key decrypt validates the private key before ciphertext shape")
    func communicationBoxPrivateKeyDecryptValidatesThePrivateKeyBeforeCiphertextShape() {
        do {
            _ = try OpalCrypto.Communication.decrypt(
                Data(),
                privateKey: Data(repeating: 0x01, count: 31)
            )
            Issue.record("Expected invalid private-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication boxes reject tampered ephemeral public keys during symmetric-key decryption")
    func communicationBoxesRejectTamperedEphemeralPublicKeysDuringSymmetricKeyDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        let message = Data("authenticated-envelope".utf8)

        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: recipientPublicKey
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey
        )

        var tamperedCiphertext = ciphertext
        tamperedCiphertext[0] = ciphertext[0] == 0x02 ? 0x03 : 0x02

        do {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                symmetricKey: decrypted.symmetricKey
            )
            Issue.record("Expected invalid ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication boxes reject structurally invalid ephemeral public keys even with a valid MAC")
    func communicationBoxesRejectStructurallyInvalidEphemeralPublicKeysEvenWithAValidMac() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        let message = Data("ephemeral-key-structure".utf8)

        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: recipientPublicKey
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey
        )

        var tamperedCiphertext = ciphertext
        tamperedCiphertext[0] = 0x04
        let authenticatedPayload = tamperedCiphertext.dropLast(16)
        let replacementAuthenticationCode = Data(
            OpalCrypto.Hashing.computeHMACSHA256(
                data: Data(authenticatedPayload),
                key: decrypted.symmetricKey
            ).prefix(16)
        )
        tamperedCiphertext.replaceSubrange(
            tamperedCiphertext.index(tamperedCiphertext.endIndex, offsetBy: -16)..<tamperedCiphertext.endIndex,
            with: replacementAuthenticationCode
        )

        do {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                symmetricKey: decrypted.symmetricKey
            )
            Issue.record("Expected malformed ephemeral public key rejection.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication box private-key decrypt reports malformed ephemeral keys as invalid ciphertext")
    func communicationBoxPrivateKeyDecryptReportsMalformedEphemeralKeysAsInvalidCiphertext() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        var ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("malformed-ephemeral-key".utf8),
            recipientPublicKey: recipientPublicKey
        )
        ciphertext[0] = 0x04

        do {
            _ = try OpalCrypto.Communication.decrypt(
                ciphertext,
                privateKey: recipientPrivateKey
            )
            Issue.record("Expected invalid ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication boxes reject non-zero plaintext padding even with a valid MAC")
    func communicationBoxesRejectNonZeroPlaintextPaddingEvenWithAValidMac() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.generatePrivateKey()
        let recipientPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: recipientPrivateKey
        )
        let message = Data("pad-check-123".utf8)

        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: recipientPublicKey,
            paddedPlaintextLength: 32
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey
        )

        let plaintext = makePaddedPlaintext(
            message: message,
            paddedPlaintextLength: 32
        )
        var tamperedPlaintext = plaintext
        tamperedPlaintext[tamperedPlaintext.index(before: tamperedPlaintext.endIndex)] = 0x01

        let ephemeralPublicKey = Data(ciphertext.prefix(33))
        let encryptedPayload = try aes256CbcCrypt(
            tamperedPlaintext,
            key: decrypted.symmetricKey,
            operation: CCOperation(kCCEncrypt)
        )
        let authenticatedPayload = ephemeralPublicKey + encryptedPayload
        let authenticationCode = Data(
            OpalCrypto.Hashing.computeHMACSHA256(
                data: authenticatedPayload,
                key: decrypted.symmetricKey
            ).prefix(16)
        )
        let tamperedCiphertext = authenticatedPayload + authenticationCode

        do {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                symmetricKey: decrypted.symmetricKey
            )
            Issue.record("Expected invalid ciphertext error for non-zero padding.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication plaintext length resolution rejects messages that overflow the 32-bit envelope length field")
    func communicationPlaintextLengthResolutionRejectsMessagesThatOverflowThe32BitEnvelopeLengthField() {
        let oversizedMessageLength = Int(UInt32.max) + 1

        do {
            _ = try CommunicationBoxModel.resolvePlaintextLength(
                messageByteCount: oversizedMessageLength,
                paddedPlaintextLength: nil
            )
            Issue.record("Expected oversized message-length rejection.")
        } catch let error as CommunicationBoxModel.Error {
            #expect(error == .messageTooLong(actual: oversizedMessageLength))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("HMAC-SHA256 helper matches a stable vector")
    func hmacSha256HelperMatchesAStableVector() throws {
        let digest = OpalCrypto.Hashing.computeHMACSHA256(
            data: Data("The quick brown fox jumps over the lazy dog".utf8),
            key: Data("key".utf8)
        )
        let expectedDigest = try Data(
            hexadecimal: "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        )

        #expect(digest == expectedDigest)
    }

    private func makePaddedPlaintext(
        message: Data,
        paddedPlaintextLength: Int
    ) -> Data {
        var plaintext = Data()
        plaintext.reserveCapacity(paddedPlaintextLength)
        plaintext.appendUInt32BigEndian(UInt32(message.count))
        plaintext.append(message)
        plaintext.append(
            Data(repeating: 0x00, count: paddedPlaintextLength - plaintext.count)
        )
        return plaintext
    }

    private func aes256CbcCrypt(
        _ input: Data,
        key: Data,
        operation: CCOperation
    ) throws -> Data {
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

        #expect(status == kCCSuccess)
        output.removeSubrange(outputLength..<output.count)
        return output
    }
}
