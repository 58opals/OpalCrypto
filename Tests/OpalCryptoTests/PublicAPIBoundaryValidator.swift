import Foundation
import Testing
import OpalCrypto

@Suite("Public API boundary validation")
struct PublicAPIBoundaryValidator {
    @Test("Exercise ECDSA sign and verify through public boundary")
    func exerciseEcdsaSignAndVerifyThroughPublicBoundary() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-message".utf8)

        let publicKeyData = try OpalCryptoBoundaryModel.SignatureModel.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )
        let signatureData = try OpalCryptoBoundaryModel.SignatureModel.sign(
            messageData: messageData,
            privateKeyData: privateKeyData,
            format: .ecdsa(.distinguishedEncodingRules)
        )

        let isValid = try OpalCryptoBoundaryModel.SignatureModel.verify(
            signatureData: signatureData,
            messageData: messageData,
            publicKeyData: publicKeyData,
            format: .ecdsa(.distinguishedEncodingRules)
        )
        #expect(isValid)
    }

    @Test("Exercise Schnorr deterministic sign and verify through public boundary")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicBoundary() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCryptoBoundaryModel.SignatureModel.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )

        let signatureData = try OpalCryptoBoundaryModel.SignatureModel.sign(
            messageData: digestData32Bytes,
            privateKeyData: privateKeyData,
            format: .schnorr,
            nonceGenerationPolicy: .bitcoinImprovementProposalSchnorrDeterministic
        )

        let isValid = try OpalCryptoBoundaryModel.SignatureModel.verify(
            signatureData: signatureData,
            messageData: digestData32Bytes,
            publicKeyData: publicKeyData,
            format: .schnorr
        )
        #expect(isValid)
    }

    @Test("Exercise hash, encoding, checksum, key-derivation, and numeric APIs")
    func exerciseHashEncodingKeyDerivationAndNumericAPIs() throws {
        let payloadData = Data("opal-api-boundary".utf8)

        let secureHashAlgorithm256 = OpalCryptoBoundaryModel.HashingModel.makeSecureHashAlgorithm256(payloadData)
        let secureHash256 = OpalCryptoBoundaryModel.HashingModel.makeSecureHash256(payloadData)
        let secureHash160 = OpalCryptoBoundaryModel.HashingModel.makeSecureHash160(payloadData)
        let hmacSecureHashAlgorithm512 = OpalCryptoBoundaryModel.HashingModel
            .makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(
                data: payloadData,
                key: Data(repeating: 0x0B, count: 16)
            )

        #expect(secureHashAlgorithm256.count == 32)
        #expect(secureHash256.count == 32)
        #expect(secureHash160.count == 20)
        #expect(hmacSecureHashAlgorithm512.count == 64)

        let base58Encoded = OpalCryptoBoundaryModel.EncodingModel.encodeBase58(payloadData)
        let base58Decoded = OpalCryptoBoundaryModel.EncodingModel.decodeBase58(base58Encoded)
        #expect(base58Decoded == payloadData)

        let base32FiveBitInput = Data([0, 1, 2, 3, 4, 5, 30, 31])
        let base32Encoded = OpalCryptoBoundaryModel.EncodingModel.encodeBase32(
            base32FiveBitInput,
            interpretedAsFiveBitValues: true
        )
        let base32Decoded = try OpalCryptoBoundaryModel.EncodingModel.decodeBase32(
            base32Encoded,
            interpretedAsFiveBitValues: true
        )
        #expect(base32Decoded == base32FiveBitInput)

        let checksumValue = OpalCryptoBoundaryModel.EncodingModel.computePolynomialModuloChecksum([1, 2, 3, 4, 5])
        #expect(checksumValue != 0)

        let derivedKey = try OpalCryptoBoundaryModel.KeyDerivationModel.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        let derivedKeyAgain = try OpalCryptoBoundaryModel.KeyDerivationModel.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        #expect(derivedKey.count == 32)
        #expect(derivedKey == derivedKeyAgain)

        var largeUnsignedInteger = OpalCryptoBoundaryModel.NumericModel.LargeUnsignedInteger(256)
        largeUnsignedInteger.multiply(by: 16)
        #expect(!largeUnsignedInteger.isZero)
        #expect(largeUnsignedInteger.serialize().count > 0)

        let unsigned256 = try OpalCryptoBoundaryModel.NumericModel.Unsigned256BitInteger(
            data32Bytes: Data(repeating: 0x01, count: 32)
        )
        let unsigned512 = try OpalCryptoBoundaryModel.NumericModel.Unsigned512BitInteger(
            data64Bytes: Data(repeating: 0x02, count: 64)
        )
        let fullWidthProduct = unsigned256.multiplyFullWidth(by: unsigned256)

        #expect(unsigned256.data32Bytes.count == 32)
        #expect(unsigned512.data64Bytes.count == 64)
        #expect(fullWidthProduct.data64Bytes.count == 64)
    }
}
