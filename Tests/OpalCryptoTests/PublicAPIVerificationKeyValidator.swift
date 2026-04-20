// PublicAPIVerificationKeyValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API verification-key validation")
struct PublicAPIVerificationKeyValidator {
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
        let truncatedUncompressedPublicKey = Data([0x04] + Array(repeating: 0x11, count: 63))

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
}
