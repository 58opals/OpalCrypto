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
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )

        let isValid = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            publicKey: publicKeyData,
            format: .der
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
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .raw
        )

        #expect(signatureData.count == 64)

        let isValid = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            publicKey: publicKeyData,
            format: .raw
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
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )
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
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )

        let isValid = try OpalCrypto.Signature.verifyECDSA(
            signature: Data(repeating: 0x00, count: 64),
            message: messageData,
            publicKey: publicKeyData,
            format: .raw
        )

        #expect(!isValid)
    }

    @Test("Exercise Schnorr deterministic sign and verify through public facade")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKeyData
        )

        let signatureData = try OpalCrypto.Signature.signSchnorr(
            digest: digestData32Bytes,
            privateKey: privateKeyData,
            noncePolicy: .bip340Deterministic
        )

        let isValid = try OpalCrypto.Signature.verifySchnorr(
            signature: signatureData,
            digest: digestData32Bytes,
            publicKey: publicKeyData
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
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )

        let rawResult = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            publicKey: verificationKey.publicKey,
            format: .der
        )
        let cachedResult = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            verificationKey: verificationKey,
            format: .der
        )

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Verification-key ECDSA verify accepts uncompressed SEC1 public keys")
    func verificationKeyEcdsaVerifyAcceptsUncompressedSec1PublicKeys() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-uncompressed-verify".utf8)
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )
        let uncompressedPublicKeyData = try Data(
            hexadecimal: """
            0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
            """
        )
        let verificationKey = try OpalCrypto.Signature.VerificationKey(
            publicKey: uncompressedPublicKeyData
        )

        let rawResult = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            publicKey: uncompressedPublicKeyData,
            format: .der
        )
        let cachedResult = try OpalCrypto.Signature.verifyECDSA(
            signature: signatureData,
            message: messageData,
            verificationKey: verificationKey,
            format: .der
        )

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Reject one-byte-short uncompressed SEC1 public keys with the uncompressed expected length")
    func rejectOneByteShortUncompressedSec1PublicKeysWithTheUncompressedExpectedLength() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-short-uncompressed-key".utf8)
        let signatureData = try OpalCrypto.Signature.signECDSA(
            message: messageData,
            privateKey: privateKeyData,
            format: .der
        )
        let truncatedUncompressedPublicKey = Data(
            [0x04]
            + Array(repeating: 0x11, count: 63)
        )

        do {
            _ = try OpalCrypto.Signature.verifyECDSA(
                signature: signatureData,
                message: messageData,
                publicKey: truncatedUncompressedPublicKey,
                format: .der
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Verification-key Schnorr verify matches raw public-key verify")
    func verificationKeySchnorrVerifyMatchesRawPublicKeyVerify() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x06
        let digestData32Bytes = Data(repeating: 0x6C, count: 32)
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
            fromPrivateKey: privateKeyData
        )
        let signatureData = try OpalCrypto.Signature.signSchnorr(
            digest: digestData32Bytes,
            privateKey: privateKeyData,
            noncePolicy: .bip340Deterministic
        )

        let rawResult = try OpalCrypto.Signature.verifySchnorr(
            signature: signatureData,
            digest: digestData32Bytes,
            publicKey: verificationKey.publicKey
        )
        let cachedResult = try OpalCrypto.Signature.verifySchnorr(
            signature: signatureData,
            digest: digestData32Bytes,
            verificationKey: verificationKey
        )

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Reject sign with invalid private key length through facade error")
    func rejectSignWithInvalidPrivateKeyLengthThroughFacadeError() {
        let messageData = Data("opal-ecdsa-message".utf8)
        let invalidPrivateKey = Data(repeating: 0x01, count: 31)

        do {
            _ = try OpalCrypto.Signature.signECDSA(
                message: messageData,
                privateKey: invalidPrivateKey,
                format: .raw
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
            _ = try OpalCrypto.Signature.verifySchnorr(
                signature: Data(repeating: 0x00, count: 64),
                digest: Data(repeating: 0xAB, count: 32),
                publicKey: Data(repeating: 0x02, count: 32)
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
            _ = try OpalCrypto.Signature.verifySchnorr(
                signature: Data(repeating: 0x00, count: 64),
                digest: Data(repeating: 0xAB, count: 32),
                publicKey: publicKeyData
            )
            Issue.record("Expected invalid public key prefix error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x04))
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

    @Test("Reject Schnorr verify with malformed SEC1 public key through facade error")
    func rejectSchnorrVerifyWithMalformedSec1PublicKeyThroughFacadeError() {
        let malformedPublicKey = Data([0x02] + Array(repeating: 0x00, count: 32))

        do {
            _ = try OpalCrypto.Signature.verifySchnorr(
                signature: Data(repeating: 0x00, count: 64),
                digest: Data(repeating: 0xAB, count: 32),
                publicKey: malformedPublicKey
            )
            Issue.record("Expected invalid public key error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr sign with invalid digest length through facade error")
    func rejectSchnorrSignWithInvalidDigestLengthThroughFacadeError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01

        do {
            _ = try OpalCrypto.Signature.signSchnorr(
                digest: Data(repeating: 0xAB, count: 31),
                privateKey: privateKeyData,
                noncePolicy: .bip340Deterministic
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

            _ = try OpalCrypto.Signature.verifySchnorr(
                signature: Data(repeating: 0x00, count: 63),
                digest: digestData32Bytes,
                publicKey: publicKeyData
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
