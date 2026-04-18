// PublicAPICommunicationValidator.swift

import Foundation
import Testing
import OpalCrypto

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
}
