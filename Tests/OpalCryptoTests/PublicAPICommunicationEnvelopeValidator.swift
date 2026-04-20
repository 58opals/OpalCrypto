// PublicAPICommunicationEnvelopeValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API communication envelope validation")
struct PublicAPICommunicationEnvelopeValidator {
    @Test("Communication encryption reports the uncompressed expected length for short SEC1 recipient keys")
    func communicationEncryptionReportsTheUncompressedExpectedLengthForShortSec1RecipientKeys() {
        let truncatedUncompressedRecipientPublicKey = Data([0x04] + Array(repeating: 0x11, count: 63))

        do {
            _ = try OpalCrypto.Communication.encrypt(
                message: Data("recipient-short-key".utf8),
                recipientPublicKey: truncatedUncompressedRecipientPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Communication box private-key decrypt validates the private key before ciphertext shape")
    func communicationBoxPrivateKeyDecryptValidatesThePrivateKeyBeforeCiphertextShape() {
        do {
            _ = try OpalCrypto.Communication.decrypt(
                Data(),
                privateKey: Data(repeating: 0x01, count: 31)
            )
            Issue.record("Expected invalid private-key length error.")
        } catch let error as OpalCrypto.Communication.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
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

    @Test("HMAC-SHA256 helper matches a stable vector")
    func hmacSha256HelperMatchesAStableVector() throws {
        let digest = OpalCrypto.Hashing.computeHMACSHA256(
            data: Data("The quick brown fox jumps over the lazy dog".utf8),
            key: Data("key".utf8)
        )
        let expectedDigest = try Data(
            hexadecimal: "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        )

        #expect(digest == expectedDigest)
    }
}
