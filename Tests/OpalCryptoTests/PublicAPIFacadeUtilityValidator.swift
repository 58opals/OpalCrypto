// PublicAPIFacadeUtilityValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade utility validation")
struct PublicAPIFacadeUtilityValidator {
    private let hash160ExpectedValue = Data([
        0xA1, 0x0C, 0xE7, 0xD9, 0x53, 0x01, 0xB2, 0xFE, 0x80, 0x43,
        0x1D, 0xF4, 0xF9, 0xE3, 0xD5, 0xD9, 0x72, 0x57, 0x07, 0x6D
    ])

    @Test("Exercise hash, encoding, checksum, key-derivation, and numeric APIs")
    func exerciseHashEncodingKeyDerivationAndNumericAPIs() throws {
        let payloadData = Data("opal-api-facade".utf8)

        let secureHashAlgorithm256 = OpalCrypto.Hashing.computeSHA256(payloadData)
        let secureHash256 = OpalCrypto.Hashing.computeHash256(payloadData)
        let secureHash160 = OpalCrypto.Hashing.computeHash160(payloadData)
        let hmacSecureHashAlgorithm512 = OpalCrypto.Hashing
            .computeHMACSHA512(
                data: payloadData,
                key: Data(repeating: 0x0B, count: 16)
            )

        #expect(secureHashAlgorithm256.count == 32)
        #expect(secureHash256.count == 32)
        #expect(secureHash160.count == 20)
        #expect(hmacSecureHashAlgorithm512.count == 64)

        let base58Encoded = OpalCrypto.Encoding.encodeBase58(payloadData)
        let base58Decoded = OpalCrypto.Encoding.decodeBase58(base58Encoded)
        #expect(base58Decoded == payloadData)

        let base32FiveBitInput = Data([0, 1, 2, 3, 4, 5, 30, 31])
        let base32Encoded = try OpalCrypto.Encoding.encodeBase32(
            base32FiveBitInput,
            interpretedAsFiveBitValues: true
        )
        let base32Decoded = try OpalCrypto.Encoding.decodeBase32(
            base32Encoded,
            interpretedAsFiveBitValues: true
        )
        #expect(base32Decoded == base32FiveBitInput)

        let checksumValue = OpalCrypto.Encoding.computePolymodChecksum([1, 2, 3, 4, 5])
        #expect(checksumValue != 0)

        let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        let derivedKeyAgain = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: Data("password".utf8),
            salt: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        #expect(derivedKey.count == 32)
        #expect(derivedKey == derivedKeyAgain)

        var largeUnsignedInteger = OpalCrypto.Numeric.BigUnsignedInteger(256)
        largeUnsignedInteger.multiply(by: 16)
        #expect(!largeUnsignedInteger.isZero)
        #expect(largeUnsignedInteger.serialize().count > 0)

        let unsigned256 = try OpalCrypto.Numeric.UInt256(
            data32Bytes: Data(repeating: 0x01, count: 32)
        )
        let unsigned512 = try OpalCrypto.Numeric.UInt512(
            data64Bytes: Data(repeating: 0x02, count: 64)
        )
        let fullWidthProduct = unsigned256.multiplyFullWidth(by: unsigned256)

        #expect(unsigned256.bytes32.count == 32)
        #expect(unsigned256.isBitSet(at: 0))
        #expect(unsigned512.bytes64.count == 64)
        #expect(fullWidthProduct.bytes64.count == 64)
    }

    @Test("Compute Hash160 known-answer value")
    func computeHash160KnownAnswerValue() {
        let payloadData = Data("opal-api-facade".utf8)
        let secureHash160 = OpalCrypto.Hashing.computeHash160(payloadData)

        #expect(secureHash160 == hash160ExpectedValue)
    }

    @Test("Exercise Base32 byte-mode round-trips with leading zero payloads")
    func exerciseBase32ByteModeRoundTripsWithLeadingZeroPayloads() throws {
        let payloads = [
            Data([0x00]),
            Data([0x00, 0x00, 0x01]),
            Data([0x00, 0x10, 0xFF, 0x00])
        ]

        for payload in payloads {
            let encoded = try OpalCrypto.Encoding.encodeBase32(
                payload,
                interpretedAsFiveBitValues: false
            )
            let decoded = try OpalCrypto.Encoding.decodeBase32(
                encoded,
                interpretedAsFiveBitValues: false
            )
            #expect(decoded == payload)
        }
    }

    @Test("Reject invalid five-bit Base32 input bytes")
    func rejectInvalidFiveBitBase32InputBytes() {
        let invalidInputs = [
            Data([0x20]),
            Data([0xFF]),
            Data([0x01, 0x20, 0x02])
        ]

        for invalidInput in invalidInputs {
            do {
                _ = try OpalCrypto.Encoding.encodeBase32(
                    invalidInput,
                    interpretedAsFiveBitValues: true
                )
                Issue.record("Expected invalid five-bit Base32 input error.")
            } catch let error as OpalCrypto.Encoding.Error {
                if case .invalidFiveBitValue(let actual) = error {
                    #expect(invalidInput.contains(actual))
                } else {
                    Issue.record("Unexpected Base32 error: \(error)")
                }
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    @Test("Reject invalid Base32 decode characters through the public facade")
    func rejectInvalidBase32DecodeCharactersThroughThePublicFacade() {
        do {
            _ = try OpalCrypto.Encoding.decodeBase32(
                "!",
                interpretedAsFiveBitValues: true
            )
            Issue.record("Expected invalid Base32 decode character error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidCharacterFound)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
