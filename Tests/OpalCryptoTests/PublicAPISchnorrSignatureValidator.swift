// PublicAPISchnorrSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API Schnorr signature validation")
struct PublicAPISchnorrSignatureValidator {
    @Test("Exercise Schnorr deterministic sign and verify through public facade")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
        let signatureData = try OpalCrypto.Signature.signSchnorr(
            digest: digestData32Bytes,
            privateKey: privateKeyData,
            noncePolicy: .bip340Deterministic
        )

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signatureData,
                digest: digestData32Bytes,
                publicKey: publicKeyData
            )
        )
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
            let publicKeyData = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKeyData)
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
