// PublicAPICommunicationCiphertextValidator.swift

import CommonCrypto
import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication ciphertext validation")
struct PublicAPICommunicationCiphertextValidator {
    @Test("Communication boxes reject tampered authentication codes")
    func communicationBoxesRejectTamperedAuthenticationCodes() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("proof".utf8),
            recipientPublicKey: recipientPublicKey
        )
        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[tamperedCiphertextData.index(before: tamperedCiphertextData.endIndex)] ^= 0x01
        let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: tamperedCiphertextData
        )

        do {
            _ = try OpalCrypto.Communication.decrypt(tamperedCiphertext, privateKey: recipientPrivateKey)
            Issue.record("Expected invalid ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication boxes reject tampered ephemeral public keys during symmetric-key decryption")
    func communicationBoxesRejectTamperedEphemeralPublicKeysDuringSymmetricKeyDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("authenticated-envelope".utf8),
            recipientPublicKey: recipientPublicKey
        )
        let decrypted = try OpalCrypto.Communication.decrypt(ciphertext, privateKey: recipientPrivateKey)

        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[0] = ciphertext.rawRepresentation[0] == 0x02 ? 0x03 : 0x02
        let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
            rawRepresentation: tamperedCiphertextData
        )

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
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: recipientPrivateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("ephemeral-key-structure".utf8),
            recipientPublicKey: recipientPublicKey
        )
        let decrypted = try OpalCrypto.Communication.decrypt(ciphertext, privateKey: recipientPrivateKey)

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
                try OpalCrypto.Communication.Ciphertext(rawRepresentation: tamperedCiphertext),
                symmetricKey: decrypted.symmetricKey
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
            recipientPublicKey: recipientPublicKey
        )
        var tamperedCiphertextData = ciphertext.rawRepresentation
        tamperedCiphertextData[0] = 0x04

        do {
            _ = try OpalCrypto.Communication.Ciphertext(rawRepresentation: tamperedCiphertextData)
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
            paddedPlaintextLength: 32
        )
        let decrypted = try OpalCrypto.Communication.decrypt(ciphertext, privateKey: recipientPrivateKey)

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
            rawRepresentation: authenticatedPayload + authenticationCode
        )

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
}
