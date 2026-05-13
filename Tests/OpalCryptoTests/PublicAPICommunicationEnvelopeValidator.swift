// PublicAPICommunicationEnvelopeValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication envelope validation")
struct PublicAPICommunicationEnvelopeValidator {
    @Test("Communication public-key values report the uncompressed expected length for short SEC1 keys")
    func communicationPublicKeyValuesReportTheUncompressedExpectedLengthForShortSec1Keys() {
        let truncatedUncompressedRecipientPublicKey = Data([0x04] + Array(repeating: 0x11, count: 63))

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: truncatedUncompressedRecipientPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication raw public-key validation treats uncompressed prefixes as length declarations")
    func communicationRawPublicKeyValidationTreatsUncompressedPrefixesAsLengthDeclarations() {
        let severelyTruncatedUncompressedRecipientPublicKey = Data([0x04] + Array(repeating: 0x11, count: 32))

        do {
            try CommunicationBoxModel.validateSecp256k1PublicKey(
                severelyTruncatedUncompressedRecipientPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as CommunicationBoxModel.Error {
            #expect(
                error == .invalidPublicKeyLength(expected: 65, actual: 33)
            )
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication private-key values reject wrong-length raw input")
    func communicationPrivateKeyValuesRejectWrongLengthRawInput() {
        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x01, count: 31)
            )
            Issue.record("Expected invalid private-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication ciphertext and symmetric-key values validate their byte shapes")
    func communicationCiphertextAndSymmetricKeyValuesValidateTheirByteShapes() throws {
        do {
            _ = try OpalCrypto.Communication.Ciphertext(rawRepresentation: Data())
            Issue.record("Expected invalid ciphertext error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: Data([0x04]) + Data(repeating: 0x01, count: 64)
            )
            Issue.record("Expected invalid ciphertext error for malformed ephemeral public key.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let privateKey = try OpalCrypto.Secp256k1.PrivateKey.generate()
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let ciphertext = try OpalCrypto.Communication.encrypt(
            message: Data("shape".utf8),
            recipientPublicKey: publicKey
        )
        do {
            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: ciphertext.rawRepresentation + Data([0x00])
            )
            Issue.record("Expected invalid ciphertext error for non-block-aligned payload.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidCiphertext)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Communication.SymmetricKey(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected invalid symmetric-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidSymmetricKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication plaintext length resolution rejects messages that overflow the 32-bit envelope length field")
    func communicationPlaintextLengthResolutionRejectsMessagesThatOverflowThe32BitEnvelopeLengthField() {
        let oversizedMessageLength = Int(UInt32.max) + 1

        do {
            _ = try CommunicationBoxModel.resolvePlaintextLength(
                messageByteCount: oversizedMessageLength,
                paddedPlaintextLength: nil
            )
            Issue.record("Expected oversized message-length rejection.")
        } catch let error as CommunicationBoxModel.Error {
            #expect(error == .messageTooLong(actual: oversizedMessageLength))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication plaintext length reports minimum violations before block alignment")
    func communicationPlaintextLengthReportsMinimumViolationsBeforeBlockAlignment() {
        do {
            _ = try CommunicationBoxModel.resolvePlaintextLength(
                messageByteCount: 4,
                paddedPlaintextLength: 5
            )
            Issue.record("Expected padded plaintext minimum-length rejection.")
        } catch let error as CommunicationBoxModel.Error {
            #expect(error == .invalidPaddedPlaintextLength(minimum: 8, actual: 5))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("HMAC-SHA256 helper matches a stable vector")
    func hmacSha256HelperMatchesAStableVector() throws {
        let digest = OpalCrypto.Hashing.hmacSHA256(
            data: Data("The quick brown fox jumps over the lazy dog".utf8),
            key: Data("key".utf8)
        )
        let expectedDigest = try Data(
            hexadecimal: "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        )

        #expect(digest == expectedDigest)
    }
}
