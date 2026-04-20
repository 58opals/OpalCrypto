// PublicAPICommunicationRoundTripValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication round-trip validation")
struct PublicAPICommunicationRoundTripValidator {
    @Test("Secp256k1 shared secrets are symmetric")
    func secp256k1SharedSecretsAreSymmetric() throws {
        let privateKeyA = try OpalCrypto.Secp256k1.generatePrivateKey()
        let publicKeyA = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: privateKeyA)
        let privateKeyB = try OpalCrypto.Secp256k1.generatePrivateKey()
        let publicKeyB = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: privateKeyB)

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
}
