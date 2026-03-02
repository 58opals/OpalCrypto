import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade utility validation")
struct PublicAPIFacadeUtilityValidator {
    @Test("Exercise hash, encoding, checksum, key-derivation, and numeric APIs")
    func exerciseHashEncodingKeyDerivationAndNumericAPIs() throws {
        let payloadData = Data("opal-api-facade".utf8)

        let secureHashAlgorithm256 = OpalCryptoFacade.Hashing.makeSecureHashAlgorithm256(payloadData)
        let secureHash256 = OpalCryptoFacade.Hashing.makeSecureHash256(payloadData)
        let secureHash160 = OpalCryptoFacade.Hashing.makeSecureHash160(payloadData)
        let hmacSecureHashAlgorithm512 = OpalCryptoFacade.Hashing
            .makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(
                data: payloadData,
                key: Data(repeating: 0x0B, count: 16)
            )

        #expect(secureHashAlgorithm256.count == 32)
        #expect(secureHash256.count == 32)
        #expect(secureHash160.count == 20)
        #expect(hmacSecureHashAlgorithm512.count == 64)

        let base58Encoded = OpalCryptoFacade.Encoding.encodeBase58(payloadData)
        let base58Decoded = OpalCryptoFacade.Encoding.decodeBase58(base58Encoded)
        #expect(base58Decoded == payloadData)

        let base32FiveBitInput = Data([0, 1, 2, 3, 4, 5, 30, 31])
        let base32Encoded = OpalCryptoFacade.Encoding.encodeBase32(
            base32FiveBitInput,
            interpretedAsFiveBitValues: true
        )
        let base32Decoded = try OpalCryptoFacade.Encoding.decodeBase32(
            base32Encoded,
            interpretedAsFiveBitValues: true
        )
        #expect(base32Decoded == base32FiveBitInput)

        let checksumValue = OpalCryptoFacade.Encoding.computePolynomialModuloChecksum([1, 2, 3, 4, 5])
        #expect(checksumValue != 0)

        let derivedKey = try OpalCryptoFacade.KeyDerivation.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        let derivedKeyAgain = try OpalCryptoFacade.KeyDerivation.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        #expect(derivedKey.count == 32)
        #expect(derivedKey == derivedKeyAgain)

        var largeUnsignedInteger = OpalCryptoFacade.Numeric.BigUnsignedInteger(256)
        largeUnsignedInteger.multiply(by: 16)
        #expect(!largeUnsignedInteger.isZero)
        #expect(largeUnsignedInteger.serialize().count > 0)

        let unsigned256 = try OpalCryptoFacade.Numeric.UInt256(
            data32Bytes: Data(repeating: 0x01, count: 32)
        )
        let unsigned512 = try OpalCryptoFacade.Numeric.UInt512(
            data64Bytes: Data(repeating: 0x02, count: 64)
        )
        let fullWidthProduct = unsigned256.multiplyFullWidth(by: unsigned256)

        #expect(unsigned256.data32Bytes.count == 32)
        #expect(unsigned512.data64Bytes.count == 64)
        #expect(fullWidthProduct.data64Bytes.count == 64)
    }
}
