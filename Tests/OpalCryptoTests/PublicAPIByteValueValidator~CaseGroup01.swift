// PublicAPIByteValueValidator~CaseGroup01.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIByteValueValidator {
    @Test("Secp256k1 byte values reject malformed raw representations")
    func rejectMalformedSecp256k1ByteValueRawRepresentations() throws {
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

    @Test("Signature digest normalizes sliced raw input")
    func signatureDigestNormalizesSlicedRawInput() throws {
        let digestData = Data(repeating: 0xAB, count: 32)
        let slicedDigestData = (Data([0xFF]) + digestData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let digest = try OpalCrypto.Signature.Digest(rawRepresentation: slicedDigestData)

        #expect(digest.rawRepresentation == digestData)
        #expect(digest.rawRepresentation.startIndex == 0)
        #expect(digest.rawRepresentation[0] == 0xAB)
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

    @Test("Communication symmetric key normalizes sliced raw input")
    func communicationSymmetricKeyNormalizesSlicedRawInput() throws {
        let symmetricKeyData = Data(repeating: 0xCD, count: 32)
        let slicedSymmetricKeyData = (Data([0xFF]) + symmetricKeyData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let symmetricKey = try OpalCrypto.Communication.SymmetricKey(
            rawRepresentation: slicedSymmetricKeyData
        )

        #expect(symmetricKey.rawRepresentation == symmetricKeyData)
        #expect(symmetricKey.rawRepresentation.startIndex == 0)
        #expect(symmetricKey.rawRepresentation[0] == 0xCD)
    }
}
