// PublicAPIHashingEncodingValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API hashing and encoding validation")
struct PublicAPIHashingEncodingValidator {
    private let hash160ShortPayloadExpectedValue = Data([
        0xA1, 0x0C, 0xE7, 0xD9, 0x53, 0x01, 0xB2, 0xFE, 0x80, 0x43,
        0x1D, 0xF4, 0xF9, 0xE3, 0xD5, 0xD9, 0x72, 0x57, 0x07, 0x6D
    ])

    @Test("Exercise hash, encoding, checksum, key-derivation, and numeric APIs")
    func exerciseHashEncodingKeyDerivationAndNumericAPIs() throws {
        let payloadData = Data("opal-api-facade".utf8)
        let secureHashAlgorithm256 = OpalCrypto.Hashing.sha256(payloadData)
        let secureHash256 = OpalCrypto.Hashing.hash256(payloadData)
        let secureHash160 = OpalCrypto.Hashing.hash160(payloadData)
        let hmacSecureHashAlgorithm512 = OpalCrypto.Hashing.hmacSHA512(
            data: payloadData,
            key: Data(repeating: 0x0B, count: 16)
        )

        #expect(secureHashAlgorithm256.count == 32)
        #expect(secureHash256.count == 32)
        #expect(secureHash160.count == 20)
        #expect(hmacSecureHashAlgorithm512.count == 64)

        let base58Encoded = OpalCrypto.Encoding.encodeBase58(payloadData)
        #expect(OpalCrypto.Encoding.decodeBase58(base58Encoded) == payloadData)

        let base32FiveBitInput = Data([0, 1, 2, 3, 4, 5, 30, 31])
        let base32FiveBitValues = try OpalCrypto.Encoding.FiveBitValues(
            rawRepresentation: base32FiveBitInput
        )
        let base32Encoded = try OpalCrypto.Encoding.encodeBase32Values(base32FiveBitValues)
        let base32Decoded = try OpalCrypto.Encoding.decodeBase32Values(base32Encoded)
        #expect(base32Decoded.rawRepresentation == base32FiveBitInput)
        #expect(
            OpalCrypto.Encoding.computePolymodChecksum(
                try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([1, 2, 3, 4, 5]))
            ) != 0
        )

        let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: Data("password".utf8),
            salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        let derivedKeyAgain = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: Data("password".utf8),
            salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        #expect(derivedKey.rawRepresentation.count == 32)
        #expect(derivedKey == derivedKeyAgain)

        var largeUnsignedInteger = OpalCrypto.Numeric.BigUnsignedInteger(256)
        largeUnsignedInteger.multiply(by: 16)
        #expect(!largeUnsignedInteger.isZero)
        #expect(largeUnsignedInteger.serialize().count > 0)
        #expect(!largeUnsignedInteger.shiftLeft(byBytes: 1).isZero)

        let unsigned256 = try OpalCrypto.Numeric.UInt256(data32Bytes: Data(repeating: 0x01, count: 32))
        let unsigned512 = try OpalCrypto.Numeric.UInt512(data64Bytes: Data(repeating: 0x02, count: 64))
        let fullWidthProduct = unsigned256.multiplyFullWidth(by: unsigned256)

        #expect(unsigned256.bytes32.count == 32)
        #expect(unsigned256.isBitSet(at: 0))
        #expect(unsigned512.bytes64.count == 64)
        #expect(fullWidthProduct.bytes64.count == 64)
    }

    @Test("Compute Hash160 known-answer values across padding boundaries")
    func computeHash160KnownAnswerValuesAcrossPaddingBoundaries() throws {
        let vectors: [(Data, Data)] = [
            (Data("opal-api-facade".utf8), hash160ShortPayloadExpectedValue),
            (Data((0..<55).map { UInt8($0) }), try Data(hexadecimal: "bf13f7b98f39c80e64ac320ce6550f2f1faa1ce1")),
            (Data((0..<56).map { UInt8($0) }), try Data(hexadecimal: "6e02e5a92245d871fa8b65679d9f2457164ecd6f")),
            (Data((0..<64).map { UInt8($0) }), try Data(hexadecimal: "dd21d9434f79e153b82e7d204ea5279200d0d022")),
            (Data((0..<80).map { UInt8($0) }), try Data(hexadecimal: "b925a791a40f5bf59ef303b00f7c9970818dbe2b"))
        ]

        for vector in vectors {
            #expect(OpalCrypto.Hashing.hash160(vector.0) == vector.1)
        }
    }

    @Test("Exercise Base32 byte-mode round-trips with leading zero payloads")
    func exerciseBase32ByteModeRoundTripsWithLeadingZeroPayloads() throws {
        for payload in [Data([0x00]), Data([0x00, 0x00, 0x01]), Data([0x00, 0x10, 0xFF, 0x00])] {
            let encoded = try OpalCrypto.Encoding.encodeBase32Bytes(payload)
            let decoded = try OpalCrypto.Encoding.decodeBase32Bytes(encoded)
            #expect(decoded == payload)
        }
    }

    @Test("Base58 encoding accepts sliced Data payloads")
    func validateBase58EncodingAcceptsSlicedDataPayloads() {
        let backingData = Data([0xFF, 0x00, 0x01, 0x02, 0x03])
        let slicedPayload = backingData.dropFirst()
        let normalizedPayload = Data(slicedPayload)
        let encoded = OpalCrypto.Encoding.encodeBase58(slicedPayload)

        #expect(encoded == OpalCrypto.Encoding.encodeBase58(normalizedPayload))
        #expect(OpalCrypto.Encoding.decodeBase58(encoded) == normalizedPayload)
    }

    @Test("Encode Base32 byte-mode using canonical known-answer strings")
    func encodeBase32ByteModeUsingCanonicalKnownAnswerStrings() throws {
        let vectors: [(Data, String)] = [
            (Data([0x00]), "q"),
            (Data([0x00, 0x00, 0x01]), "qqp"),
            (Data([0x00, 0x10, 0xFF, 0x00]), "qpplcq")
        ]

        for vector in vectors {
            let encoded = try OpalCrypto.Encoding.encodeBase32Bytes(vector.0)
            #expect(encoded == vector.1)
        }
    }

    @Test("Decode Base32 byte-mode known-answer strings with leading zero prefixes")
    func decodeBase32ByteModeKnownAnswerStringsWithLeadingZeroPrefixes() throws {
        let vectors: [(String, Data)] = [
            ("q", Data([0x00])),
            ("qqp", Data([0x00, 0x00, 0x01])),
            ("qqqz", Data([0x00, 0x00, 0x00, 0x02])),
            ("qq0n4", Data([0x00, 0x00, 0x3E, 0x75]))
        ]

        for vector in vectors {
            let decoded = try OpalCrypto.Encoding.decodeBase32Bytes(vector.0)
            #expect(decoded == vector.1)
        }
    }

    @Test("Reject invalid single-byte five-bit Base32 input bytes exactly")
    func rejectInvalidSingleByteFiveBitBase32InputBytesExactly() {
        for invalidInput in [(Data([0x20]), UInt8(0x20)), (Data([0xFF]), UInt8(0xFF))] {
            do {
                _ = try OpalCrypto.Encoding.FiveBitValues(
                    rawRepresentation: invalidInput.0
                )
                Issue.record("Expected invalid five-bit Base32 input error.")
            } catch let error as OpalCrypto.Encoding.Error {
                if case .invalidFiveBitValue(let actual) = error {
                    #expect(actual == invalidInput.1)
                } else {
                    Issue.record("Unexpected Base32 error: \(error)")
                }
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    @Test("Five-bit values normalize sliced raw input")
    func normalizeFiveBitValuesFromSlicedRawInput() throws {
        let fiveBitValueData = Data([0x01, 0x02, 0x1F])
        let slicedFiveBitValueData = (Data([0xFF]) + fiveBitValueData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let fiveBitValues = try OpalCrypto.Encoding.FiveBitValues(
            rawRepresentation: slicedFiveBitValueData
        )

        #expect(fiveBitValues.rawRepresentation == fiveBitValueData)
        #expect(fiveBitValues.rawRepresentation.startIndex == 0)
        #expect(fiveBitValues.rawRepresentation[0] == 0x01)
    }

    @Test("Reject mixed five-bit Base32 input at the exact offending byte")
    func rejectMixedFiveBitBase32InputAtTheExactOffendingByte() {
        do {
            _ = try OpalCrypto.Encoding.FiveBitValues(
                rawRepresentation: Data([0x01, 0x20, 0x02])
            )
            Issue.record("Expected invalid five-bit Base32 input error.")
        } catch let error as OpalCrypto.Encoding.Error {
            if case .invalidFiveBitValue(let actual) = error {
                #expect(actual == 0x20)
            } else {
                Issue.record("Unexpected Base32 error: \(error)")
            }
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject invalid Base32 decode characters through the public facade")
    func rejectInvalidBase32DecodeCharactersThroughThePublicFacade() {
        do {
            _ = try OpalCrypto.Encoding.decodeBase32Values("!")
            Issue.record("Expected invalid Base32 decode character error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidCharacterFound)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject mixed-case Base32 decode in five-bit mode")
    func rejectMixedCaseBase32DecodeInFiveBitMode() {
        do {
            _ = try OpalCrypto.Encoding.decodeBase32Values("qP")
            Issue.record("Expected mixed-case Base32 decode error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidCharacterFound)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject mixed-case Base32 decode in byte mode")
    func rejectMixedCaseBase32DecodeInByteMode() {
        do {
            _ = try OpalCrypto.Encoding.decodeBase32Bytes("qP")
            Issue.record("Expected mixed-case Base32 decode error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidCharacterFound)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
