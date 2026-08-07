// PublicAPINostrImplementationPossibility44Validator.swift

import Foundation
import OpalCrypto
import Testing

@Suite("Public API NIP-44 version 2 validation")
struct PublicAPINostrImplementationPossibility44Validator {
    private let expectedConversationKey = try! Data(
        hexadecimal:
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
    )
    private let officialPayload =
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"

    @Test("Derive the official symmetric conversation key")
    func deriveOfficialSymmetricConversationKey() throws {
        let firstSigningKey = try makeSigningKey(1)
        let secondSigningKey = try makeSigningKey(2)

        let firstResult = OpalCrypto.Nostr.NIP44.deriveConversationKey(
            signingKey: firstSigningKey,
            publicKey: secondSigningKey.bip340VerificationKey
        )
        let secondResult = OpalCrypto.Nostr.NIP44.deriveConversationKey(
            signingKey: secondSigningKey,
            publicKey: firstSigningKey.bip340VerificationKey
        )

        #expect(firstResult.rawRepresentation == expectedConversationKey)
        #expect(secondResult == firstResult)
    }

    @Test("Encrypt and decrypt the official payload vector")
    func encryptAndDecryptOfficialPayloadVector() throws {
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        let nonce = try OpalCrypto.Nostr.NIP44.Nonce(
            rawRepresentation: Data(repeating: 0, count: 31) + Data([1])
        )

        let encrypted = try OpalCrypto.Nostr.NIP44.encrypt(
            "a",
            conversationKey: conversationKey,
            nonce: nonce,
            maximumPlaintextByteCount: 1
        )
        #expect(encrypted.encodedRepresentation == officialPayload)

        let imported = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: officialPayload,
            maximumEncodedPayloadByteCount: officialPayload.utf8.count
        )
        let decrypted = try OpalCrypto.Nostr.NIP44.decrypt(
            imported,
            conversationKey: conversationKey,
            maximumPlaintextByteCount: 1
        )
        #expect(decrypted == "a")
    }

    @Test("Round trip UTF-8 text with secure random nonces")
    func roundTripUTF8TextWithSecureRandomNonces() throws {
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        let plaintext = "Mosaic relay payload \u{1F9E9}"
        let payload = try OpalCrypto.Nostr.NIP44.encrypt(
            plaintext,
            conversationKey: conversationKey,
            maximumPlaintextByteCount: 1_024
        )

        #expect(
            try OpalCrypto.Nostr.NIP44.decrypt(
                payload,
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 1_024
            ) == plaintext
        )
    }

    @Test("Match a second official Unicode payload vector")
    func matchSecondOfficialUnicodePayloadVector() throws {
        let signingKey = try makeSigningKey(2)
        let peer = try makeSigningKey(1).bip340VerificationKey
        let conversationKey = OpalCrypto.Nostr.NIP44.deriveConversationKey(
            signingKey: signingKey,
            publicKey: peer
        )
        let nonce = try OpalCrypto.Nostr.NIP44.Nonce(
            rawRepresentation: try Data(
                hexadecimal:
                    "f00000000000000000000000000000f00000000000000000000000000000000f"
            )
        )
        let expected =
            "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj"

        let payload = try OpalCrypto.Nostr.NIP44.encrypt(
            "🍕🫃",
            conversationKey: conversationKey,
            nonce: nonce,
            maximumPlaintextByteCount: 8
        )

        #expect(payload.encodedRepresentation == expected)
    }

    @Test("Match the official extended-prefix payload hashes")
    func matchOfficialExtendedPrefixPayloadHashes() throws {
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        let nonce = try OpalCrypto.Nostr.NIP44.Nonce(
            rawRepresentation: Data(repeating: 0, count: 31) + Data([1])
        )
        let vectors = [
            (65_535, "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"),
            (65_536, "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"),
            (65_537, "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435")
        ]

        for (length, expectedHash) in vectors {
            let payload = try OpalCrypto.Nostr.NIP44.encrypt(
                String(repeating: "a", count: length),
                conversationKey: conversationKey,
                nonce: nonce,
                maximumPlaintextByteCount: length
            )
            #expect(
                hexadecimal(
                    OpalCrypto.Hashing.sha256(
                        Data(payload.encodedRepresentation.utf8)
                    )
                ) == expectedHash
            )
            #expect(
                try OpalCrypto.Nostr.NIP44.decrypt(
                    payload,
                    conversationKey: conversationKey,
                    maximumPlaintextByteCount: length
                ) == String(repeating: "a", count: length)
            )
        }
    }

    @Test("Reject malformed keys nonces and allocation bounds")
    func rejectMalformedKeysNoncesAndAllocationBounds() throws {
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.ConversationKey(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.Nonce(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.encrypt(
                "",
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 1
            )
        }
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.encrypt(
                "too long",
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 3
            )
        }
        #expect(
            throws: OpalCrypto.Nostr.NIP44.Error
                .invalidMaximumPlaintextByteCount(0)
        ) {
            _ = try OpalCrypto.Nostr.NIP44.encrypt(
                "x",
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 0
            )
        }
    }

    @Test("Reject malformed unsupported and oversized payloads")
    func rejectMalformedUnsupportedAndOversizedPayloads() throws {
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.unsupportedEncoding) {
            _ = try OpalCrypto.Nostr.NIP44.Payload(
                encodedRepresentation: "#",
                maximumEncodedPayloadByteCount: 132
            )
        }
        var unsupportedVersion = try #require(
            Data(base64Encoded: officialPayload)
        )
        unsupportedVersion[unsupportedVersion.startIndex] = 3
        let unsupportedPayload = unsupportedVersion.base64EncodedString()
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.Payload(
                encodedRepresentation: unsupportedPayload,
                maximumEncodedPayloadByteCount: unsupportedPayload.utf8.count
            )
        }
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.self) {
            _ = try OpalCrypto.Nostr.NIP44.Payload(
                encodedRepresentation: officialPayload,
                maximumEncodedPayloadByteCount: 131
            )
        }
    }

    @Test("Reject ciphertext outside the decryption work bound")
    func rejectCiphertextOutsideDecryptionWorkBound() throws {
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        let payload = try OpalCrypto.Nostr.NIP44.encrypt(
            String(repeating: "a", count: 33),
            conversationKey: conversationKey,
            nonce: try .init(
                rawRepresentation: Data(repeating: 0, count: 31) + Data([1])
            ),
            maximumPlaintextByteCount: 33
        )

        #expect(throws: OpalCrypto.Nostr.NIP44.Error.invalidPayload) {
            _ = try OpalCrypto.Nostr.NIP44.decrypt(
                payload,
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 1
            )
        }
    }

    @Test("Reject authenticated payload tampering")
    func rejectAuthenticatedPayloadTampering() throws {
        var tamperedBytes = try #require(Data(base64Encoded: officialPayload))
        tamperedBytes[tamperedBytes.startIndex + 40] ^= 0x01
        let tamperedRepresentation = tamperedBytes.base64EncodedString()
        let tamperedPayload = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: tamperedRepresentation,
            maximumEncodedPayloadByteCount: tamperedRepresentation.utf8.count
        )
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )

        #expect(throws: OpalCrypto.Nostr.NIP44.Error.authenticationFailed) {
            _ = try OpalCrypto.Nostr.NIP44.decrypt(
                tamperedPayload,
                conversationKey: conversationKey,
                maximumPlaintextByteCount: 1
            )
        }
    }

    @Test("Reject a wrong conversation key and official invalid padding")
    func rejectWrongConversationKeyAndOfficialInvalidPadding() throws {
        let imported = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: officialPayload,
            maximumEncodedPayloadByteCount: officialPayload.utf8.count
        )
        let wrongKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: Data(repeating: 0x42, count: 32)
        )
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.authenticationFailed) {
            _ = try OpalCrypto.Nostr.NIP44.decrypt(
                imported,
                conversationKey: wrongKey,
                maximumPlaintextByteCount: 1
            )
        }

        let invalidPaddingRepresentation =
            "Anq2XbuLvCuONcr7V0UxTh8FAyWoZNEdBHXvdbNmDZHB573MI7R7rrTYftpqmvUpahmBC2sngmI14/L0HjOZ7lWGJlzdh6luiOnGPc46cGxf08MRC4CIuxx3i2Lm0KqgJ7vA"
        let invalidPaddingPayload = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: invalidPaddingRepresentation,
            maximumEncodedPayloadByteCount:
                invalidPaddingRepresentation.utf8.count
        )
        let invalidPaddingKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: try Data(
                hexadecimal:
                    "5254827d29177622d40a7b67cad014fe7137700c3c523903ebbe3e1b74d40214"
            )
        )
        #expect(throws: OpalCrypto.Nostr.NIP44.Error.invalidPadding) {
            _ = try OpalCrypto.Nostr.NIP44.decrypt(
                invalidPaddingPayload,
                conversationKey: invalidPaddingKey,
                maximumPlaintextByteCount: 128
            )
        }
    }

    @Test("Payload equality ignores caller-owned parsing limits")
    func payloadEqualityIgnoresCallerOwnedParsingLimits() throws {
        let exact = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: officialPayload,
            maximumEncodedPayloadByteCount: officialPayload.utf8.count
        )
        let largerPolicy = try OpalCrypto.Nostr.NIP44.Payload(
            encodedRepresentation: officialPayload,
            maximumEncodedPayloadByteCount: officialPayload.utf8.count + 128
        )

        #expect(exact == largerPolicy)
    }

    @Test("Redact NIP-44 secret-bearing descriptions")
    func redactSecretBearingDescriptions() throws {
        let conversationKey = try OpalCrypto.Nostr.NIP44.ConversationKey(
            rawRepresentation: expectedConversationKey
        )
        let nonce = try OpalCrypto.Nostr.NIP44.Nonce(
            rawRepresentation: expectedConversationKey
        )

        #expect(String(describing: conversationKey).contains("redacted"))
        #expect(String(reflecting: conversationKey).contains("redacted"))
        #expect(String(describing: nonce).contains("redacted"))
        #expect(String(reflecting: nonce).contains("redacted"))
    }

    private func makeSigningKey(
        _ value: UInt8
    ) throws -> OpalCrypto.Secp256k1.SigningKey {
        try OpalCrypto.Secp256k1.SigningKey(
            rawRepresentation: Data(repeating: 0, count: 31) + Data([value])
        )
    }

    private func hexadecimal(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
