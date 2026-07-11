// PublicAPIECDSASignatureValidator~Signing.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIECDSASignatureValidator {
    @Test("Exercise ECDSA sign and verify through public facade")
    func exerciseEcdsaSignAndVerifyThroughPublicFacade() throws {
        let privateKey = try makePrivateKey(1)
        let message = Data("opal-ecdsa-message".utf8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signature = try OpalCrypto.Signature.ECDSA.signSHA256(
            message: message,
            privateKey: privateKey,
            format: .der
        )

        #expect(try signature.verifySHA256(message: message, publicKey: publicKey))
    }

    @Test("Exercise ECDSA raw sign and verify through public facade")
    func exerciseEcdsaRawSignAndVerifyThroughPublicFacade() throws {
        let privateKey = try makePrivateKey(1)
        let message = Data("opal-ecdsa-raw-message".utf8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .raw
        )

        #expect(signature.rawRepresentation.count == 64)
        #expect(try signature.verify(message: message, publicKey: publicKey))
    }

    @Test("Exercise ECDSA digest sign and verify without double hashing")
    func exerciseEcdsaDigestSignAndVerifyWithoutDoubleHashing() throws {
        let privateKey = try makePrivateKey(1)
        let message = Data("opal-ecdsa-digest-message".utf8)
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: OpalCrypto.Hashing.sha256(message)
        )
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let verificationKey = OpalCrypto.Signature.VerificationKey(publicKey: publicKey)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            digest: digest,
            privateKey: privateKey,
            format: .raw
        )

        #expect(try signature.verify(digest: digest, publicKey: publicKey))
        #expect(try signature.verify(digest: digest, verificationKey: verificationKey))
        #expect(!(try signature.verify(message: digest.rawRepresentation, publicKey: publicKey)))
    }

    @Test("SigningKey ECDSA message signing matches legacy deterministic output")
    func signingKeyECDSAMessageSigningMatchesLegacyDeterministicOutput() throws {
        let privateKey = try makePrivateKey(1)
        let signingKey = privateKey.makeSigningKey()
        let message = Data("opal-ecdsa-signing-key-message".utf8)
        let legacySignature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        )
        let signingKeySignature = try signingKey.signECDSA(
            message: message,
            format: .der
        )

        #expect(signingKeySignature.rawRepresentation == legacySignature.rawRepresentation)
        #expect(try signingKeySignature.verify(message: message, publicKey: signingKey.publicKey))
        #expect(try signingKeySignature.verify(message: message, verificationKey: signingKey.verificationKey))
    }

    @Test("SigningKey ECDSA digest signing matches legacy deterministic output")
    func signingKeyECDSADigestSigningMatchesLegacyDeterministicOutput() throws {
        let privateKey = try makePrivateKey(1)
        let signingKey = privateKey.makeSigningKey()
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: OpalCrypto.Hashing.sha256(Data("opal-ecdsa-signing-key-digest".utf8))
        )
        let legacySignature = try OpalCrypto.Signature.ECDSA.sign(
            digest: digest,
            privateKey: privateKey,
            format: .raw
        )
        let signingKeySignature = try signingKey.signECDSA(
            digest: digest,
            format: .raw
        )

        #expect(signingKeySignature.rawRepresentation == legacySignature.rawRepresentation)
        #expect(try signingKeySignature.verify(digest: digest, publicKey: signingKey.publicKey))
        #expect(try signingKeySignature.verify(digest: digest, verificationKey: signingKey.verificationKey))
    }

    @Test("Reject ECDSA verification for tampered message and wrong public key")
    func rejectEcdsaVerificationForTamperedMessageAndWrongPublicKey() throws {
        let privateKey = try makePrivateKey(1)
        let otherPrivateKey = try makePrivateKey(2)
        let message = Data("opal-ecdsa-message".utf8)
        var tamperedMessage = message
        tamperedMessage[tamperedMessage.index(before: tamperedMessage.endIndex)] ^= 0x01

        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let otherPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: otherPrivateKey)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        )

        #expect(!(try signature.verify(message: tamperedMessage, publicKey: publicKey)))
        #expect(!(try signature.verify(message: message, publicKey: otherPublicKey)))
    }
}
