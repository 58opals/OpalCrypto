// PublicAPIHashingEncodingValidator~Contract.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIHashingEncodingValidator {
    @Test("Base58 decoding exposes optional and validating failure contracts")
    func exposeOptionalAndValidatingBase58DecodeContracts() throws {
        let expectedBytes = Data([0x00, 0x01, 0x02])
        let encoded = OpalCrypto.Encoding.encodeBase58(expectedBytes)

        #expect(
            OpalCrypto.Encoding.decodeBase58IfValid(
                encoded,
                maximumDecodedByteCount: expectedBytes.count
            ) == expectedBytes
        )
        #expect(
            try OpalCrypto.Encoding.decodeBase58Validating(
                encoded,
                maximumDecodedByteCount: expectedBytes.count
            ) == expectedBytes
        )
        #expect(
            OpalCrypto.Encoding.decodeBase58IfValid(
                "0",
                maximumDecodedByteCount: expectedBytes.count
            ) == nil
        )
        #expect(throws: OpalCrypto.Encoding.Base58DecodingError.invalidText) {
            _ = try OpalCrypto.Encoding.decodeBase58Validating(
                "0",
                maximumDecodedByteCount: expectedBytes.count
            )
        }
    }

    @Test("Reject Base58 output beyond the caller-provided byte limit")
    func rejectBase58OutputBeyondCallerProvidedByteLimit() throws {
        let payload = Data([0x00, 0x01, 0x02])
        let encoded = OpalCrypto.Encoding.encodeBase58(payload)

        #expect(
            OpalCrypto.Encoding.decodeBase58IfValid(
                encoded,
                maximumDecodedByteCount: payload.count - 1
            ) == nil
        )
        #expect(
            throws: OpalCrypto.Encoding.Base58DecodingError
                .decodedDataExceedsMaximumByteCount(maximum: payload.count - 1)
        ) {
            _ = try OpalCrypto.Encoding.decodeBase58Validating(
                encoded,
                maximumDecodedByteCount: payload.count - 1
            )
        }
        #expect(
            throws: OpalCrypto.Encoding.Base58DecodingError
                .invalidMaximumDecodedByteCount(actual: -1)
        ) {
            _ = try OpalCrypto.Encoding.decodeBase58Validating(
                encoded,
                maximumDecodedByteCount: -1
            )
        }
    }

    @Test("Reject Base32 byte output beyond the caller-provided byte limit")
    func rejectBase32ByteOutputBeyondCallerProvidedByteLimit() {
        #expect(
            throws: OpalCrypto.Encoding.Error
                .decodedDataExceedsMaximumByteCount(maximum: 2)
        ) {
            _ = try OpalCrypto.Encoding.decodeBase32Bytes(
                "qqp",
                maximumDecodedByteCount: 2
            )
        }
        #expect(
            throws: OpalCrypto.Encoding.Error.invalidMaximumDecodedByteCount(actual: -1)
        ) {
            _ = try OpalCrypto.Encoding.decodeBase32Bytes(
                "q",
                maximumDecodedByteCount: -1
            )
        }
    }

    @Test("Base32 encoding offers nonthrowing byte and typed-value operations")
    func offerNonthrowingBase32EncodingOperations() throws {
        let bytes = Data([0x00, 0x10, 0xFF])
        let values = try OpalCrypto.Encoding.FiveBitValues(
            rawRepresentation: Data([0, 1, 30, 31])
        )

        #expect(OpalCrypto.Encoding.encodeBase32(bytes: bytes) == "qy8l")
        #expect(OpalCrypto.Encoding.encodeBase32(values: values) == "qp7l")
        #expect(
            try OpalCrypto.Encoding.encodeBase32Bytes(bytes)
                == OpalCrypto.Encoding.encodeBase32(bytes: bytes)
        )
        #expect(
            try OpalCrypto.Encoding.encodeBase32Values(values)
                == OpalCrypto.Encoding.encodeBase32(values: values)
        )
    }
}
