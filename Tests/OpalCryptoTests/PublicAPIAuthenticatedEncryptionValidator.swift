// PublicAPIAuthenticatedEncryptionValidator.swift

import Foundation
import OpalCrypto
import Testing

@Suite("Public API authenticated-encryption validation")
struct PublicAPIAuthenticatedEncryptionValidator {
    @Test("AES-256-GCM matches the NIST CAVP authenticated-data vector")
    func matchAES256GCMNISTCAVPVector() throws {
        // NIST CAVP gcmEncryptExtIV256.rsp, Keylen 256, IVlen 96,
        // PTlen 128, AADlen 128, Taglen 128, Count 0.
        // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
        let key = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Key(
            rawRepresentation: Data(
                hexadecimal: "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b"
            )
        )
        let nonce = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Nonce(
            rawRepresentation: Data(hexadecimal: "ac93a1a6145299bde902f21a")
        )
        let plaintext = try Data(hexadecimal: "2d71bcfa914e4ac045b2aa60955fad24")
        let authenticatedData = try Data(hexadecimal: "1e0889016f67601c8ebea4943bc23ad6")
        let expectedCombinedRepresentation = try Data(
            hexadecimal: "ac93a1a6145299bde902f21a8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab"
        )

        let sealedBox = try OpalCrypto.AuthenticatedEncryption.AES256GCM.seal(
            plaintext,
            using: key,
            authenticating: authenticatedData,
            nonce: nonce
        )

        #expect(sealedBox.combinedRepresentation == expectedCombinedRepresentation)
        #expect(
            try OpalCrypto.AuthenticatedEncryption.AES256GCM.open(
                sealedBox,
                using: key,
                authenticating: authenticatedData
            ) == plaintext
        )
    }

    @Test("AES-256-GCM imports bounded sealed boxes and rejects authentication changes")
    func importBoundedSealedBoxAndRejectAuthenticationChanges() throws {
        let key = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Key(
            rawRepresentation: Data(repeating: 0xA5, count: 32)
        )
        let authenticatedData = Data("scope-a".utf8)
        let sealedBox = try OpalCrypto.AuthenticatedEncryption.AES256GCM.seal(
            Data("private snapshot".utf8),
            using: key,
            authenticating: authenticatedData
        )
        let imported = try OpalCrypto.AuthenticatedEncryption.AES256GCM.SealedBox(
            combinedRepresentation: sealedBox.combinedRepresentation,
            maximumCombinedByteCount: sealedBox.combinedRepresentation.count
        )

        #expect(
            try OpalCrypto.AuthenticatedEncryption.AES256GCM.open(
                imported,
                using: key,
                authenticating: authenticatedData
            ) == Data("private snapshot".utf8)
        )
        #expect(throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error.authenticationFailed) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.open(
                imported,
                using: key,
                authenticating: Data("scope-b".utf8)
            )
        }
    }

    @Test("AES-256-GCM validates key nonce and sealed-box boundaries")
    func validateAES256GCMBoundaries() {
        #expect(
            throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error.invalidKeyLength(
                expected: 32,
                actual: 31
            )
        ) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Key(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        #expect(
            throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error.invalidNonceLength(
                expected: 12,
                actual: 11
            )
        ) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Nonce(
                rawRepresentation: Data(repeating: 0, count: 11)
            )
        }
        #expect(
            throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error
                .invalidMaximumCombinedByteCount(minimum: 28, actual: 27)
        ) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.SealedBox(
                combinedRepresentation: Data(repeating: 0, count: 28),
                maximumCombinedByteCount: 27
            )
        }
        #expect(
            throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error
                .combinedByteCountExceedsMaximum(maximum: 28, actual: 29)
        ) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.SealedBox(
                combinedRepresentation: Data(repeating: 0, count: 29),
                maximumCombinedByteCount: 28
            )
        }
        #expect(throws: OpalCrypto.AuthenticatedEncryption.AES256GCM.Error.malformedSealedBox) {
            _ = try OpalCrypto.AuthenticatedEncryption.AES256GCM.SealedBox(
                combinedRepresentation: Data(repeating: 0, count: 27),
                maximumCombinedByteCount: 28
            )
        }
    }

    @Test("AES-256-GCM key and nonce descriptions stay redacted")
    func redactAES256GCMKeyAndNonceDescriptions() throws {
        let key = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Key(
            rawRepresentation: Data(repeating: 0xA5, count: 32)
        )
        let nonce = try OpalCrypto.AuthenticatedEncryption.AES256GCM.Nonce(
            rawRepresentation: Data(repeating: 0x5A, count: 12)
        )

        #expect(key.description.contains("redacted"))
        #expect(!key.description.contains("a5a5"))
        #expect(key.debugDescription == key.description)
        #expect(nonce.description.contains("redacted"))
        #expect(!nonce.description.contains("5a5a"))
        #expect(nonce.debugDescription == nonce.description)
    }
}
