// PublicAPIHashingEncodingValidator~Contract.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIHashingEncodingValidator {
    @Test("Base58 decoding exposes optional and validating failure contracts")
    func exposeOptionalAndValidatingBase58DecodeContracts() throws {
        let expectedBytes = Data([0x00, 0x01, 0x02])
        let encoded = OpalCrypto.Encoding.encodeBase58(expectedBytes)

        #expect(OpalCrypto.Encoding.decodeBase58IfValid(encoded) == expectedBytes)
        #expect(try OpalCrypto.Encoding.decodeBase58Validating(encoded) == expectedBytes)
        #expect(OpalCrypto.Encoding.decodeBase58IfValid("0") == nil)
        #expect(throws: OpalCrypto.Encoding.Base58DecodingError.invalidText) {
            _ = try OpalCrypto.Encoding.decodeBase58Validating("0")
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
