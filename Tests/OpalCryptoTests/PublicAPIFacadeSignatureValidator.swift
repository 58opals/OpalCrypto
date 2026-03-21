// PublicAPIFacadeSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade signature validation")
struct PublicAPIFacadeSignatureValidator {
    @Test("Exercise ECDSA sign and verify through public facade")
    func exerciseEcdsaSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-message".utf8)

        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: messageData,
            privateKey: privateKeyData,
            format: .ecdsa(.der)
        )

        let isValid = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: messageData,
            publicKey: publicKeyData,
            format: .ecdsa(.der)
        )
        #expect(isValid)
    }

    @Test("Exercise ECDSA raw sign and verify through public facade")
    func exerciseEcdsaRawSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-raw-message".utf8)

        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: messageData,
            privateKey: privateKeyData,
            format: .ecdsa(.raw)
        )

        #expect(signatureData.count == 64)

        let isValid = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: messageData,
            publicKey: publicKeyData,
            format: .ecdsa(.raw)
        )
        #expect(isValid)
    }

    @Test("Reject ECDSA verification for tampered message and wrong public key")
    func rejectEcdsaVerificationForTamperedMessageAndWrongPublicKey() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        var otherPrivateKeyData = Data(repeating: 0x00, count: 32)
        otherPrivateKeyData[31] = 0x02
        let messageData = Data("opal-ecdsa-message".utf8)
        var tamperedMessageData = messageData
        tamperedMessageData[tamperedMessageData.index(before: tamperedMessageData.endIndex)] ^= 0x01

        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )
        let otherPublicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: otherPrivateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: messageData,
            privateKey: privateKeyData,
            format: .ecdsa(.der)
        )

        let isValidForTamperedMessage = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: tamperedMessageData,
            publicKey: publicKeyData,
            format: .ecdsa(.der)
        )
        let isValidForWrongPublicKey = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: messageData,
            publicKey: otherPublicKeyData,
            format: .ecdsa(.der)
        )

        #expect(!isValidForTamperedMessage)
        #expect(!isValidForWrongPublicKey)
    }

    @Test("Reject ECDSA raw verify with invalid signature length through facade error")
    func rejectEcdsaRawVerifyWithInvalidSignatureLengthThroughFacadeError() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-raw-message".utf8)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: messageData,
            privateKey: privateKeyData,
            format: .ecdsa(.raw)
        )

        do {
            _ = try OpalCrypto.Signature.verify(
                signature: Data(signatureData.prefix(63)),
                message: messageData,
                publicKey: publicKeyData,
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Exercise Schnorr deterministic sign and verify through public facade")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )

        let signatureData = try OpalCrypto.Signature.sign(
            message: digestData32Bytes,
            privateKey: privateKeyData,
            format: .schnorr,
            nonce: .bip340Deterministic
        )

        let isValid = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: digestData32Bytes,
            publicKey: publicKeyData,
            format: .schnorr
        )
        #expect(isValid)
    }

    @Test("Verification-key ECDSA verify matches raw public-key verify")
    func verificationKeyEcdsaVerifyMatchesRawPublicKeyVerify() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x05
        let messageData = Data("opal-ecdsa-cached-verify".utf8)
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: messageData,
            privateKey: privateKeyData,
            format: .ecdsa(.der)
        )

        let rawResult = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: messageData,
            publicKey: verificationKey.publicKey,
            format: .ecdsa(.der)
        )
        let cachedResult = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: messageData,
            verificationKey: verificationKey,
            format: .ecdsa(.der)
        )

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Verification-key Schnorr verify matches raw public-key verify")
    func verificationKeySchnorrVerifyMatchesRawPublicKeyVerify() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x06
        let digestData32Bytes = Data(repeating: 0x6C, count: 32)
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.sign(
            message: digestData32Bytes,
            privateKey: privateKeyData,
            format: .schnorr,
            nonce: .bip340Deterministic
        )

        let rawResult = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: digestData32Bytes,
            publicKey: verificationKey.publicKey,
            format: .schnorr
        )
        let cachedResult = try OpalCrypto.Signature.verify(
            signature: signatureData,
            message: digestData32Bytes,
            verificationKey: verificationKey,
            format: .schnorr
        )

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Reject sign with invalid private key length through facade error")
    func rejectSignWithInvalidPrivateKeyLengthThroughFacadeError() {
        let messageData = Data("opal-ecdsa-message".utf8)
        let invalidPrivateKey = Data(repeating: 0x01, count: 31)

        do {
            _ = try OpalCrypto.Signature.sign(
                message: messageData,
                privateKey: invalidPrivateKey,
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key length through facade error")
    func rejectVerifyWithInvalidPublicKeyLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Signature.verify(
                signature: Data(repeating: 0x00, count: 64),
                message: Data(repeating: 0xAB, count: 32),
                publicKey: Data(repeating: 0x02, count: 32),
                format: .schnorr
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKeyLength(expected: 33, actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key prefix through facade error")
    func rejectVerifyWithInvalidPublicKeyPrefixThroughFacadeError() {
        var publicKeyData = Data(repeating: 0x00, count: 33)
        publicKeyData[0] = 0x04

        do {
            _ = try OpalCrypto.Signature.verify(
                signature: Data(repeating: 0x00, count: 64),
                message: Data(repeating: 0xAB, count: 32),
                publicKey: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid public key prefix error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x04))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr sign with invalid digest length through facade error")
    func rejectSchnorrSignWithInvalidDigestLengthThroughFacadeError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01

        do {
            _ = try OpalCrypto.Signature.sign(
                message: Data(repeating: 0xAB, count: 31),
                privateKey: privateKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid digest length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidDigestLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr verify with invalid signature length through facade error")
    func rejectSchnorrVerifyWithInvalidSignatureLengthThroughFacadeError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x03
        let digestData32Bytes = Data(repeating: 0xCD, count: 32)

        do {
            let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
                fromPrivateKey: privateKeyData
            )

            _ = try OpalCrypto.Signature.verify(
                signature: Data(repeating: 0x00, count: 63),
                message: digestData32Bytes,
                publicKey: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
