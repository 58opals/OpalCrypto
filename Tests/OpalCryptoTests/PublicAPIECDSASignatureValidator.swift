// PublicAPIECDSASignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API ECDSA signature validation")
struct PublicAPIECDSASignatureValidator {
    @Test("Exercise ECDSA sign and verify through public facade")
    func exerciseEcdsaSignAndVerifyThroughPublicFacade() throws {
        let privateKey = try makePrivateKey(1)
        let message = Data("opal-ecdsa-message".utf8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        )

        #expect(try signature.verify(message: message, publicKey: publicKey))
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

    @Test("Reject ECDSA raw construction with invalid signature length through facade error")
    func rejectEcdsaRawConstructionWithInvalidSignatureLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Signature.ECDSA(
                rawRepresentation: Data(repeating: 0x01, count: 63),
                format: .raw
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("ECDSA raw construction rejects invalid signature scalars")
    func ecdsaRawConstructionRejectsInvalidSignatureScalars() {
        do {
            _ = try OpalCrypto.Signature.ECDSA(
                rawRepresentation: Data(repeating: 0x00, count: 64),
                format: .raw
            )
            Issue.record("Expected invalid signature error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("ECDSA signature values normalize sliced raw input")
    func normalizeECDSASignatureValuesFromSlicedRawInput() throws {
        let rawSignature = Data(repeating: 0x00, count: 31) + Data([0x01])
            + Data(repeating: 0x00, count: 31) + Data([0x02])
        let slicedRawSignature = (Data([0xFF]) + rawSignature + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let rawSignatureValue = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: slicedRawSignature,
            format: .raw
        )
        let derSignature = try rawSignatureValue.encoded(as: .der).rawRepresentation
        let slicedDERSignature = (Data([0xFF]) + derSignature + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let derSignatureValue = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: slicedDERSignature,
            format: .der
        )

        #expect(rawSignatureValue.rawRepresentation == rawSignature)
        #expect(rawSignatureValue.rawRepresentation.startIndex == 0)
        #expect(rawSignatureValue.rawRepresentation[0] == 0x00)
        #expect(derSignatureValue.rawRepresentation == derSignature)
        #expect(derSignatureValue.rawRepresentation.startIndex == 0)
        #expect(try derSignatureValue.encoded(as: .raw).rawRepresentation == rawSignature)
    }

    @Test("ECDSA DER construction accepts sliced Data payloads")
    func ecdsaDerConstructionAcceptsSlicedDataPayloads() throws {
        let rawSignature = Data(repeating: 0x00, count: 31) + Data([0x01])
            + Data(repeating: 0x00, count: 31) + Data([0x02])
        let derSignature = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: rawSignature,
            format: .raw
        ).encoded(as: .der).rawRepresentation
        let slicedDerSignature = (Data([0xFF]) + derSignature).dropFirst()

        let reparsedSignature = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: slicedDerSignature,
            format: .der
        )

        #expect(try reparsedSignature.encoded(as: .raw).rawRepresentation == rawSignature)
    }

    @Test("Reject private-key construction with invalid private key length through facade error")
    func rejectPrivateKeyConstructionWithInvalidPrivateKeyLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x01, count: 31)
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject private-key construction with invalid private key value through facade error")
    func rejectPrivateKeyConstructionWithInvalidPrivateKeyValueThroughFacadeError() {
        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x00, count: 32)
            )
            Issue.record("Expected invalid private key error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject ECDSA verify with malformed SEC1 public key through facade error")
    func rejectEcdsaVerifyWithMalformedSec1PublicKeyThroughFacadeError() {
        let malformedPublicKey = Data([0x02] + Array(repeating: 0x00, count: 32))

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: malformedPublicKey)
            Issue.record("Expected invalid public key error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    private func makePrivateKey(_ value: UInt8) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
