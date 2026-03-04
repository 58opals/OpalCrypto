import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade utility validation")
struct PublicAPIFacadeUtilityValidator {
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
        let base32Encoded = OpalCrypto.Encoding.encodeBase32(
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
}
