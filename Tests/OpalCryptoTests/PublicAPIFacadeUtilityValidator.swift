// PublicAPIFacadeUtilityValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade utility validation")
struct PublicAPIFacadeUtilityValidator {
    private let hash160ShortPayloadExpectedValue = Data([
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
        #expect(!largeUnsignedInteger.shiftLeft(byBytes: 1).isZero)

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

    @Test("Reject invalid PBKDF2 parameters through facade errors")
    func rejectInvalidPbkdf2ParametersThroughFacadeErrors() {
        let invalidCases: [(Int, Int?, Data, OpalCrypto.KeyDerivation.Error)] = [
            (0, 32, Data("salt".utf8), .invalidIterationCount(actual: 0)),
            (-1, 32, Data("salt".utf8), .invalidIterationCount(actual: -1)),
            (16, 0, Data("salt".utf8), .invalidDerivedKeyLength(actual: 0)),
            (16, -1, Data("salt".utf8), .invalidDerivedKeyLength(actual: -1)),
            (16, 32, Data(), .emptySalt)
        ]

        for invalidCase in invalidCases {
            do {
                _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                    password: Data("password".utf8),
                    salt: invalidCase.2,
                    iterationCount: invalidCase.0,
                    derivedKeyLength: invalidCase.1
                )
                Issue.record("Expected invalid PBKDF2 parameter error.")
            } catch let error as OpalCrypto.KeyDerivation.Error {
                #expect(error == invalidCase.3)
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    @Test("Reject PBKDF2 key lengths beyond the RFC maximum")
    func rejectPbkdf2KeyLengthsBeyondTheRfcMaximum() {
        let maximumDerivedKeyLength = Int(UInt64(UInt32.max) * 64)
        let oversizedDerivedKeyLength = maximumDerivedKeyLength + 1

        do {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("password".utf8),
                salt: Data("salt".utf8),
                iterationCount: 16,
                derivedKeyLength: oversizedDerivedKeyLength
            )
            Issue.record("Expected oversized PBKDF2 key-length error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .derivedKeyLengthExceedsLimit(actual: oversizedDerivedKeyLength))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject BigUnsignedInteger division by zero")
    func rejectBigUnsignedIntegerDivisionByZero() {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(256)

        do {
            _ = try value.divide(by: 0)
            Issue.record("Expected invalid divisor error.")
        } catch let error as OpalCrypto.Numeric.Error {
            #expect(error == .invalidDivisor(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Compute Hash160 known-answer values across padding boundaries")
    func computeHash160KnownAnswerValuesAcrossPaddingBoundaries() throws {
        let vectors: [(payload: Data, expectedDigest: Data)] = [
            (
                Data("opal-api-facade".utf8),
                hash160ShortPayloadExpectedValue
            ),
            (
                Data((0..<55).map { UInt8($0) }),
                try Data(hexadecimal: "bf13f7b98f39c80e64ac320ce6550f2f1faa1ce1")
            ),
            (
                Data((0..<56).map { UInt8($0) }),
                try Data(hexadecimal: "6e02e5a92245d871fa8b65679d9f2457164ecd6f")
            ),
            (
                Data((0..<64).map { UInt8($0) }),
                try Data(hexadecimal: "dd21d9434f79e153b82e7d204ea5279200d0d022")
            ),
            (
                Data((0..<80).map { UInt8($0) }),
                try Data(hexadecimal: "b925a791a40f5bf59ef303b00f7c9970818dbe2b")
            )
        ]

        for vector in vectors {
            #expect(OpalCrypto.Hashing.computeHash160(vector.payload) == vector.expectedDigest)
        }
    }

    @Test("Multiply BigUnsignedInteger by a large 64-bit multiplier at the overflow boundary")
    func multiplyBigUnsignedIntegerByLarge64BitMultiplierAtTheOverflowBoundary() {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(
            Data([0xFF, 0xFF, 0xFF, 0xFF])
        )

        value.multiply(by: 4_294_967_298)

        #expect(value.serialize() == Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE
        ]))
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

    @Test("Encode Base32 byte-mode using canonical known-answer strings")
    func encodeBase32ByteModeUsingCanonicalKnownAnswerStrings() throws {
        let vectors: [(payload: Data, expectedEncoding: String)] = [
            (Data([0x00]), "q"),
            (Data([0x00, 0x00, 0x01]), "qqp"),
            (Data([0x00, 0x10, 0xFF, 0x00]), "qpplcq")
        ]

        for vector in vectors {
            let encoded = try OpalCrypto.Encoding.encodeBase32(
                vector.payload,
                interpretedAsFiveBitValues: false
            )
            #expect(encoded == vector.expectedEncoding)
        }
    }

    @Test("Decode Base32 byte-mode known-answer strings with leading zero prefixes")
    func decodeBase32ByteModeKnownAnswerStringsWithLeadingZeroPrefixes() throws {
        let vectors: [(encoded: String, expectedPayload: Data)] = [
            ("q", Data([0x00])),
            ("qqp", Data([0x00, 0x00, 0x01])),
            ("qqqz", Data([0x00, 0x00, 0x00, 0x02])),
            ("qq0n4", Data([0x00, 0x00, 0x3E, 0x75]))
        ]

        for vector in vectors {
            let decoded = try OpalCrypto.Encoding.decodeBase32(
                vector.encoded,
                interpretedAsFiveBitValues: false
            )
            #expect(decoded == vector.expectedPayload)
        }
    }

    @Test("Reject invalid single-byte five-bit Base32 input bytes exactly")
    func rejectInvalidSingleByteFiveBitBase32InputBytesExactly() {
        let invalidInputs: [(input: Data, expectedActual: UInt8)] = [
            (Data([0x20]), 0x20),
            (Data([0xFF]), 0xFF)
        ]

        for invalidInput in invalidInputs {
            do {
                _ = try OpalCrypto.Encoding.encodeBase32(
                    invalidInput.input,
                    interpretedAsFiveBitValues: true
                )
                Issue.record("Expected invalid five-bit Base32 input error.")
            } catch let error as OpalCrypto.Encoding.Error {
                if case .invalidFiveBitValue(let actual) = error {
                    #expect(actual == invalidInput.expectedActual)
                } else {
                    Issue.record("Unexpected Base32 error: \(error)")
                }
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    @Test("Reject mixed five-bit Base32 input at the exact offending byte")
    func rejectMixedFiveBitBase32InputAtTheExactOffendingByte() {
        let invalidInput = Data([0x01, 0x20, 0x02])

        do {
            _ = try OpalCrypto.Encoding.encodeBase32(
                invalidInput,
                interpretedAsFiveBitValues: true
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

    @Test("Reject mixed-case Base32 decode in five-bit mode")
    func rejectMixedCaseBase32DecodeInFiveBitMode() {
        do {
            _ = try OpalCrypto.Encoding.decodeBase32(
                "qP",
                interpretedAsFiveBitValues: true
            )
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
            _ = try OpalCrypto.Encoding.decodeBase32(
                "qP",
                interpretedAsFiveBitValues: false
            )
            Issue.record("Expected mixed-case Base32 decode error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidCharacterFound)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}

private extension Data {
    init(hexadecimal: String) throws {
        let normalized = hexadecimal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count.isMultiple(of: 2) else {
            throw HexadecimalDataError.invalidLength
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(normalized.count / 2)
        var cursor = normalized.startIndex
        while cursor < normalized.endIndex {
            let nextCursor = normalized.index(cursor, offsetBy: 2)
            let pair = normalized[cursor..<nextCursor]
            guard let byte = UInt8(pair, radix: 16) else {
                throw HexadecimalDataError.invalidCharacter
            }
            bytes.append(byte)
            cursor = nextCursor
        }
        self = Data(bytes)
    }
}

private enum HexadecimalDataError: Error {
    case invalidLength
    case invalidCharacter
}
