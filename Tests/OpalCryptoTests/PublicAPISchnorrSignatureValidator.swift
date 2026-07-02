// PublicAPISchnorrSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API Schnorr signature validation")
struct PublicAPISchnorrSignatureValidator {
    @Test("Exercise Schnorr deterministic sign and verify through public facade")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicFacade() throws {
        let privateKey = try makePrivateKey(2)
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0xAB, count: 32)
        )
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bip340Deterministic
        )

        #expect(try signature.verify(digest: digest, publicKey: publicKey))
    }

    @Test("SigningKey Schnorr signing matches legacy deterministic output")
    func signingKeySchnorrSigningMatchesLegacyDeterministicOutput() throws {
        let privateKey = try makePrivateKey(2)
        let signingKey = try privateKey.makeSigningKey()
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0xCD, count: 32)
        )
        let legacySignature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bip340Deterministic
        )
        let signingKeySignature = try signingKey.signSchnorr(
            digest: digest,
            noncePolicy: .bip340Deterministic
        )

        #expect(signingKeySignature.rawRepresentation == legacySignature.rawRepresentation)
        #expect(try signingKeySignature.verify(digest: digest, publicKey: signingKey.publicKey))
        #expect(try signingKeySignature.verify(digest: digest, verificationKey: signingKey.verificationKey))
    }

    @Test("Reject public-key construction with invalid public key length through facade error")
    func rejectPublicKeyConstructionWithInvalidPublicKeyLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: Data(repeating: 0x02, count: 32)
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyLength(expected: 33, actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject public-key construction with invalid public key prefix through facade error")
    func rejectPublicKeyConstructionWithInvalidPublicKeyPrefixThroughFacadeError() {
        var publicKeyData = Data(repeating: 0x00, count: 33)
        publicKeyData[0] = 0x05

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: publicKeyData)
            Issue.record("Expected invalid public key prefix error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x05))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr verify with malformed SEC1 public key through facade error")
    func rejectSchnorrVerifyWithMalformedSec1PublicKeyThroughFacadeError() {
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

    @Test("Reject Schnorr digest construction with invalid digest length through facade error")
    func rejectSchnorrDigestConstructionWithInvalidDigestLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: 0xAB, count: 31)
            )
            Issue.record("Expected invalid digest length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidDigestLength(expected: 32, actual: 31))
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

    @Test("Reject Schnorr signature construction with invalid signature length through facade error")
    func rejectSchnorrSignatureConstructionWithInvalidSignatureLengthThroughFacadeError() {
        do {
            _ = try OpalCrypto.Signature.Schnorr(
                rawRepresentation: Data(repeating: 0x00, count: 63)
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr signature construction with non-canonical field and scalar components")
    func rejectSchnorrSignatureConstructionWithNonCanonicalFieldAndScalarComponents() throws {
        let fieldPrime = try Data(
            hexadecimal: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        )
        let curveOrder = try Data(
            hexadecimal: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        let one = Data(repeating: 0x00, count: 31) + Data([0x01])

        for invalidSignature in [fieldPrime + one, one + curveOrder] {
            do {
                _ = try OpalCrypto.Signature.Schnorr(rawRepresentation: invalidSignature)
                Issue.record("Expected invalid Schnorr signature rejection.")
            } catch let error as OpalCrypto.Signature.Error {
                #expect(error == .invalidSignature)
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    private func makePrivateKey(_ value: UInt8) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
