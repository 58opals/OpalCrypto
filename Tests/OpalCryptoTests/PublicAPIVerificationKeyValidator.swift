// PublicAPIVerificationKeyValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API verification-key validation")
struct PublicAPIVerificationKeyValidator {
    @Test("Verification-key ECDSA verify matches public-key verify")
    func verificationKeyEcdsaVerifyMatchesPublicKeyVerify() throws {
        let privateKey = try makePrivateKey(5)
        let message = Data("opal-ecdsa-cached-verify".utf8)
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(from: privateKey)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        )

        let rawResult = try signature.verify(message: message, publicKey: verificationKey.publicKey)
        let cachedResult = try signature.verify(message: message, verificationKey: verificationKey)

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Verification-key ECDSA verify accepts uncompressed SEC1 public keys")
    func verificationKeyEcdsaVerifyAcceptsUncompressedSec1PublicKeys() throws {
        let privateKey = try makePrivateKey(1)
        let message = Data("opal-ecdsa-uncompressed-verify".utf8)
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        )
        let uncompressedPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: Data(
                hexadecimal: """
                0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
                """
            )
        )
        let verificationKey = OpalCrypto.Signature.VerificationKey(
            publicKey: uncompressedPublicKey
        )

        let rawResult = try signature.verify(message: message, publicKey: uncompressedPublicKey)
        let cachedResult = try signature.verify(message: message, verificationKey: verificationKey)

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    @Test("Verification-key raw representation initializes and normalizes SEC1 keys")
    func verificationKeyRawRepresentationInitializesAndNormalizesSec1Keys() throws {
        let uncompressedPublicKeyData = try Data(
            hexadecimal: """
            0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
            """
        )
        let verificationKey = try OpalCrypto.Signature.VerificationKey(
            rawRepresentation: uncompressedPublicKeyData
        )
        let compressedPublicKeyData = try Data(
            hexadecimal: """
            0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
            """
        )

        #expect(verificationKey.rawRepresentation == compressedPublicKeyData)
    }

    @Test("Verification-key raw representation rejects malformed SEC1 keys")
    func verificationKeyRawRepresentationRejectsMalformedSec1Keys() {
        do {
            _ = try OpalCrypto.Signature.VerificationKey(
                rawRepresentation: Data([0x04] + Array(repeating: 0x11, count: 63))
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject one-byte-short uncompressed SEC1 public keys with the uncompressed expected length")
    func rejectOneByteShortUncompressedSec1PublicKeysWithTheUncompressedExpectedLength() {
        let truncatedUncompressedPublicKey = Data([0x04] + Array(repeating: 0x11, count: 63))

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: truncatedUncompressedPublicKey
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Verification-key Schnorr verify matches public-key verify")
    func verificationKeySchnorrVerifyMatchesPublicKeyVerify() throws {
        let privateKey = try makePrivateKey(6)
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0x6C, count: 32)
        )
        let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(from: privateKey)
        let signature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bchDeterministic
        )

        let rawResult = try signature.verify(digest: digest, publicKey: verificationKey.publicKey)
        let cachedResult = try signature.verify(digest: digest, verificationKey: verificationKey)

        #expect(rawResult == cachedResult)
        #expect(cachedResult)
    }

    private func makePrivateKey(_ value: UInt8) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
