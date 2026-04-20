// PublicAPIECDSASignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API ECDSA signature validation")
struct PublicAPIECDSASignatureValidator {
    @Test("Exercise ECDSA sign and verify through public facade")
    func exerciseEcdsaSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-message".utf8)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )

        #expect(
            try OpalCrypto.Signature.verifyECDSA(
                signature: signatureData,
                message: messageData,
                publicKey: publicKeyData,
                format: .der
            )
        )
    }

    @Test("Exercise ECDSA raw sign and verify through public facade")
    func exerciseEcdsaRawSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-raw-message".utf8)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .raw
        )

        #expect(signatureData.count == 64)
        #expect(
            try OpalCrypto.Signature.verifyECDSA(
                signature: signatureData,
                message: messageData,
                publicKey: publicKeyData,
                format: .raw
            )
        )
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

        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
        let otherPublicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: otherPrivateKeyData
        )
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )

        let isValidForTamperedMessage = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: tamperedMessageData,
            publicKey: publicKeyData,
            format: .der
        )
        let isValidForWrongPublicKey = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            publicKey: otherPublicKeyData,
            format: .der
        )

        #expect(!isValidForTamperedMessage)
        #expect(!isValidForWrongPublicKey)
    }

    @Test("Reject ECDSA raw verify with invalid signature length through facade error")
    func rejectEcdsaRawVerifyWithInvalidSignatureLengthThroughFacadeError() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-raw-message".utf8)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .raw
        )

        do {
            _ = try OpalCrypto.Signature.verifyECDSA(
                signature: Data(signatureData.prefix(63)),
                message: messageData,
                publicKey: publicKeyData,
                format: .raw
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("ECDSA raw verify returns false for invalid signature scalars")
    func ecdsaRawVerifyReturnsFalseForInvalidSignatureScalars() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-invalid-scalar".utf8)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)

        let isValid = try OpalCrypto.Signature.verifyECDSA(
            signature: Data(repeating: 0x00, count: 64),
            message: messageData,
            publicKey: publicKeyData,
            format: .raw
        )

        #expect(!isValid)
    }

    @Test("Reject sign with invalid private key length through facade error")
    func rejectSignWithInvalidPrivateKeyLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Signature.signECDSA(
                message: Data("opal-ecdsa-message".utf8),
                privateKey: Data(repeating: 0x01, count: 31),
                format: .raw
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject ECDSA verify with malformed SEC1 public key through facade error")
    func rejectEcdsaVerifyWithMalformedSec1PublicKeyThroughFacadeError() {
        let malformedPublicKey = Data([0x02] + Array(repeating: 0x00, count: 32))

        do {
            _ = try OpalCrypto.Signature.verifyECDSA(
                signature: Data(repeating: 0x00, count: 64),
                message: Data("opal-ecdsa-message".utf8),
                publicKey: malformedPublicKey,
                format: .raw
            )
            Issue.record("Expected invalid public key error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
