// PublicAPIByteValueValidator~CaseGroup01.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIByteValueValidator {
    @Test("Secp256k1 byte values reject malformed raw representations")
    func rejectMalformedSecp256k1ByteValueRawRepresentations() throws {
        #expect(throws: OpalCrypto.Secp256k1.Error.invalidPrivateKeyLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: Data(repeating: 0x01, count: 31))
        }

        #expect(throws: OpalCrypto.Secp256k1.Error.invalidPrivateKey) {
            _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: Data(repeating: 0x00, count: 32))
        }

        #expect(throws: OpalCrypto.Secp256k1.Error.invalidPublicKeyPrefix(actual: 0x05)) {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: Data([0x05]) + Data(repeating: 0x01, count: 32)
            )
        }

        #expect(throws: OpalCrypto.Secp256k1.Error.invalidTweakLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: Data(repeating: 0x01, count: 31))
        }

        #expect(throws: OpalCrypto.Secp256k1.Error.invalidTweak) {
            _ = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: Data(repeating: 0xff, count: 32))
        }

        #expect(throws: OpalCrypto.Secp256k1.Error.invalidDerivedKey) {
            _ = try OpalCrypto.Secp256k1.SharedSecret(rawRepresentation: Data(repeating: 0x01, count: 31))
        }
    }

    @Test("Public keys reject incorrect widths and invalid curve points")
    func rejectPublicKeyWidthAndCurvePointFailures() {
        #expect(throws: OpalCrypto.Secp256k1.Error.invalidPublicKeyLength(expected: 33, actual: 32)) {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: Data(repeating: 0x02, count: 32)
            )
        }
        #expect(throws: OpalCrypto.Secp256k1.Error.invalidPublicKey) {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: Data([0x02] + Array(repeating: 0x00, count: 32))
            )
        }
    }

    @Test("Signature byte values reject malformed raw representations")
    func signatureByteValuesRejectMalformedRawRepresentations() throws {
        #expect(throws: OpalCrypto.Signature.Error.invalidDigestLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0x01, count: 31))
        }

        #expect(throws: OpalCrypto.Signature.Error.invalidSignatureLength(expected: 64, actual: 63)) {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: Data(repeating: 0x01, count: 63), format: .raw)
        }

        #expect(throws: OpalCrypto.Signature.Error.invalidDER) {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: Data([0x30, 0x01, 0x00]), format: .der)
        }

        #expect(throws: OpalCrypto.Signature.Error.invalidSignatureLength(expected: 64, actual: 63)) {
            _ = try OpalCrypto.Signature.Schnorr(rawRepresentation: Data(repeating: 0x01, count: 63))
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
        #expect(throws: OpalCrypto.Communication.Error.invalidCiphertext) {
            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: Data(),
                maximumCiphertextByteCount: 65
            )
        }

        #expect(throws: OpalCrypto.Communication.Error.invalidSymmetricKeyLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Communication.SymmetricKey(rawRepresentation: Data(repeating: 0x01, count: 31))
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
