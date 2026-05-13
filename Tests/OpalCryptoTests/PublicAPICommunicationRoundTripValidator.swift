// PublicAPICommunicationRoundTripValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication round-trip validation")
struct PublicAPICommunicationRoundTripValidator {
    @Test("Secp256k1 shared secrets are symmetric")
    func validateSecp256k1SharedSecretsAreSymmetric() throws {
        let privateKeyA = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let publicKeyA = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKeyA)
        let privateKeyB = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let publicKeyB = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKeyB)

        let sharedSecretAB = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyA,
            publicKey: publicKeyB
        )
        let sharedSecretBA = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyB,
            publicKey: publicKeyA
        )

        #expect(sharedSecretAB == sharedSecretBA)
        #expect(sharedSecretAB.rawRepresentation.count == 32)
    }

    @Test("Communication boxes round-trip through private and symmetric decryption")
    func communicationBoxesRoundTripThroughPrivateAndSymmetricDecryption() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let recipientPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
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
            ).rawRepresentation.count == 65
        )
    }

    @Test("Communication encryption accepts uncompressed recipient public keys")
    func communicationEncryptionAcceptsUncompressedRecipientPublicKeys() throws {
        let recipientPrivateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let uncompressedRecipientPublicKeyData = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.derivePublicKey(
                fromPrivateKeyData32Bytes: recipientPrivateKey.rawRepresentation,
                format: .uncompressed
            )
        let uncompressedRecipientPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: uncompressedRecipientPublicKeyData
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
