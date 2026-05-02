// PublicAPIByteValueValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API byte-value validation")
struct PublicAPIByteValueValidator {
    @Test("Secp256k1 byte values reject malformed raw representations")
    func secp256k1ByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected private-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: Data(repeating: 0x00, count: 32))
            Issue.record("Expected invalid private-key error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: Data([0x05]) + Data(repeating: 0x01, count: 32)
            )
            Issue.record("Expected public-key prefix error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x05))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected scalar length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidTweakLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: Data(repeating: 0xff, count: 32))
            Issue.record("Expected invalid scalar error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidTweak)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Secp256k1.SharedSecret(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected shared-secret length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidDerivedKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Signature byte values reject malformed raw representations")
    func signatureByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected digest length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidDigestLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: Data(repeating: 0x01, count: 63), format: .raw)
            Issue.record("Expected ECDSA signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: Data([0x30, 0x01, 0x00]), format: .der)
            Issue.record("Expected DER signature error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidDER)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Signature.Schnorr(rawRepresentation: Data(repeating: 0x01, count: 63))
            Issue.record("Expected Schnorr signature length error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication byte values reject malformed raw representations")
    func communicationByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Communication.Ciphertext(rawRepresentation: Data())
            Issue.record("Expected ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Communication.SymmetricKey(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected symmetric-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidSymmetricKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Pedersen byte values reject malformed raw representations")
    func pedersenByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected nonce length error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidNonceLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0xff, count: 32))
            Issue.record("Expected invalid nonce error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidNonce)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Pedersen.CommitmentPoint(rawRepresentation: Data(repeating: 0x01, count: 32))
            Issue.record("Expected commitment length error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidCommitmentLength(actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Key, derivation, and encoding byte values reject malformed raw representations")
    func keyDerivationAndEncodingByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Key.Seed(rawRepresentation: Data(repeating: 0x01, count: 15))
            Issue.record("Expected seed length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidSeedLength(actual: 15))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.ChainCode(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected chain-code length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidChainCodeLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.Fingerprint(rawRepresentation: Data(repeating: 0x01, count: 3))
            Issue.record("Expected fingerprint length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidParentFingerprintLength(expected: 4, actual: 3))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data())
            Issue.record("Expected empty salt error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .emptySalt)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.KeyDerivation.DerivedKey(rawRepresentation: Data())
            Issue.record("Expected derived-key length error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .invalidDerivedKeyLength(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([0x01, 0x20, 0x02]))
            Issue.record("Expected five-bit value error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidFiveBitValue(actual: 0x20))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
