// PublicAPICommunicationCiphertextValidator.swift

import CommonCrypto
import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication ciphertext validation")
struct PublicAPICommunicationCiphertextValidator {
    @Test("Communication ciphertext values normalize sliced raw input")
    func normalizeCommunicationCiphertextValuesFromSlicedRawInput() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("sliced-ciphertext".utf8),
            recipientPublicKey: recipientPublicKey,
            maximumCiphertextByteCount: 81
        )
        let slicedCiphertextData = (Data([0xFF]) + ciphertext.rawRepresentation + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let normalizedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: slicedCiphertextData,
            maximumCiphertextByteCount: 81
        )

        #expect(normalizedCiphertext.rawRepresentation == ciphertext.rawRepresentation)
        #expect(normalizedCiphertext.rawRepresentation.startIndex == 0)
        #expect(normalizedCiphertext.rawRepresentation[0] == ciphertext.rawRepresentation[0])
    }

    @Test("Unchecked communication ciphertext values normalize sliced raw input")
    func normalizeUncheckedCommunicationCiphertextValuesFromSlicedRawInput() throws {
        let ciphertextData = Data([0x02] + Array(repeating: 0x01, count: 64))
        let slicedCiphertextData = (Data([0xFF]) + ciphertextData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let ciphertext = OpalCrypto.Communication.Ciphertext(
            unchecked: slicedCiphertextData
        )

        #expect(ciphertext.rawRepresentation == ciphertextData)
        #expect(ciphertext.rawRepresentation.startIndex == 0)
        #expect(ciphertext.rawRepresentation[0] == 0x02)
    }

    @Test("Communication boxes reject too-short ciphertext during private-key decryption")
    func rejectTooShortCiphertextDuringPrivateKeyDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let tooShortCiphertext = OpalCrypto.Communication.Ciphertext(
            unchecked: Data([0x02])
        )

        #expect(throws: OpalCrypto.Communication.Error.invalidCiphertext) {
            _ = try OpalCrypto.Communication.decrypt(
                tooShortCiphertext,
                privateKey: recipientPrivateKey,
                maximumCiphertextByteCount: 1
            )
        }
    }

    @Test("Communication boxes reject tampered authentication codes")
    func communicationBoxesRejectTamperedAuthenticationCodes() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("proof".utf8),
            recipientPublicKey: recipientPublicKey,
            maximumCiphertextByteCount: 65
        )
        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[tamperedCiphertextData.index(before: tamperedCiphertextData.endIndex)] ^= 0x01
        let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: tamperedCiphertextData,
            maximumCiphertextByteCount: 65
        )

        #expect(throws: OpalCrypto.Communication.Error.invalidCiphertext) {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                privateKey: recipientPrivateKey,
                maximumCiphertextByteCount: 65
            )
        }
    }

    @Test("Communication boxes reject tampered ephemeral public keys during symmetric-key decryption")
    func communicationBoxesRejectTamperedEphemeralPublicKeysDuringSymmetricKeyDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("authenticated-envelope".utf8),
            recipientPublicKey: recipientPublicKey,
            maximumCiphertextByteCount: 81
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey,
            maximumCiphertextByteCount: 81
        )

        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[0] = ciphertext.rawRepresentation[0] == 0x02 ? 0x03 : 0x02
        let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: tamperedCiphertextData,
            maximumCiphertextByteCount: 81
        )

        do {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                symmetricKey: decrypted.symmetricKey,
                maximumCiphertextByteCount: 81
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
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("ephemeral-key-structure".utf8),
            recipientPublicKey: recipientPublicKey,
            maximumCiphertextByteCount: 81
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey,
            maximumCiphertextByteCount: 81
        )

        var tamperedCiphertext = ciphertext.rawRepresentation
        tamperedCiphertext[0] = 0x04
        let authenticatedPayload = tamperedCiphertext.dropLast(16)
        let replacementAuthenticationCode = Data(
            OpalCrypto.Hashing.hmacSHA256(
                data: Data(authenticatedPayload),
                key: decrypted.symmetricKey.rawRepresentation
            ).prefix(16)
        )
        tamperedCiphertext.replaceSubrange(
            tamperedCiphertext.index(tamperedCiphertext.endIndex, offsetBy: -16)..<tamperedCiphertext.endIndex,
            with: replacementAuthenticationCode
        )

        do {
            _ = try OpalCrypto.Communication.decrypt(
                try OpalCrypto.Communication.Ciphertext(
                    rawRepresentation: tamperedCiphertext,
                    maximumCiphertextByteCount: 81
                ),
                symmetricKey: decrypted.symmetricKey,
                maximumCiphertextByteCount: 81
            )
            Issue.record("Expected malformed ephemeral public key rejection.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication ciphertext construction rejects malformed ephemeral keys")
    func communicationCiphertextConstructionRejectsMalformedEphemeralKeys() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("malformed-ephemeral-key".utf8),
            recipientPublicKey: recipientPublicKey,
            maximumCiphertextByteCount: 81
        )
        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[0] = 0x04

        do {
            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: tamperedCiphertextData,
                maximumCiphertextByteCount: 81
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
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let message = Data("pad-check-123".utf8)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: message,
            recipientPublicKey: recipientPublicKey,
            paddedPlaintextLength: 32,
            maximumCiphertextByteCount: 81
        )
        let decrypted = try OpalCrypto.Communication.decrypt(
            ciphertext,
            privateKey: recipientPrivateKey,
            maximumCiphertextByteCount: 81
        )

        var tamperedPlaintext = OpalCryptoTestSupport.makePaddedPlaintext(
            message: message,
            paddedPlaintextLength: 32
        )
        tamperedPlaintext[tamperedPlaintext.index(before: tamperedPlaintext.endIndex)] = 0x01

        let ephemeralPublicKey = Data(ciphertext.rawRepresentation.prefix(33))
        let encryptedPayload = try OpalCryptoTestSupport.aes256CbcCrypt(
            tamperedPlaintext,
            key: decrypted.symmetricKey.rawRepresentation,
            operation: CCOperation(kCCEncrypt)
        )
        let authenticatedPayload = ephemeralPublicKey + encryptedPayload
        let authenticationCode = Data(
            OpalCrypto.Hashing.hmacSHA256(
                data: authenticatedPayload,
                key: decrypted.symmetricKey.rawRepresentation
            ).prefix(16)
        )
        let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: authenticatedPayload + authenticationCode,
            maximumCiphertextByteCount: 81
        )

        do {
            _ = try OpalCrypto.Communication.decrypt(
                tamperedCiphertext,
                symmetricKey: decrypted.symmetricKey,
                maximumCiphertextByteCount: 81
            )
            Issue.record("Expected invalid ciphertext error for non-zero padding.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication ciphertext import rejects over-budget input before validation and copying")
    func rejectCommunicationCiphertextImportOverBudgetBeforeValidationAndCopying() {
        let overBudgetInput = Data(repeating: 0x00, count: 66)

        #expect(
            throws: OpalCrypto.Communication.Error
                .ciphertextByteCountExceedsMaximum(maximum: 65, actual: 66)
        ) {
            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: overBudgetInput,
                maximumCiphertextByteCount: 65
            )
        }
    }

    @Test("Communication decryption rejects a ciphertext above its caller-provided budget")
    func rejectCommunicationDecryptionAboveCallerProvidedBudget() throws {
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data(),
            recipientPublicKey: publicKey,
            maximumCiphertextByteCount: 65
        )

        #expect(
            throws: OpalCrypto.Communication.Error
                .ciphertextByteCountExceedsMaximum(maximum: 64, actual: 65)
        ) {
            _ = try OpalCrypto.Communication.decrypt(
                ciphertext,
                privateKey: privateKey,
                maximumCiphertextByteCount: 64
            )
        }
    }
}
