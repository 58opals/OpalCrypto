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

        let publicKeyData = try OpalCryptoBoundaryModel.Signature.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )
        let signatureData = try OpalCryptoBoundaryModel.Signature.sign(
            messageData: messageData,
            privateKeyData: privateKeyData,
            format: .ecdsa(.der)
        )

        let isValid = try OpalCryptoBoundaryModel.Signature.verify(
            signatureData: signatureData,
            messageData: messageData,
            publicKeyData: publicKeyData,
            format: .ecdsa(.der)
        )
        #expect(isValid)
    }

    @Test("Exercise Schnorr deterministic sign and verify through public boundary")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicBoundary() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCryptoBoundaryModel.Signature.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )

        let signatureData = try OpalCryptoBoundaryModel.Signature.sign(
            messageData: digestData32Bytes,
            privateKeyData: privateKeyData,
            format: .schnorr,
            noncePolicy: .bitcoinImprovementProposalSchnorrDeterministic
        )

        let isValid = try OpalCryptoBoundaryModel.Signature.verify(
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

        let secureHashAlgorithm256 = OpalCryptoBoundaryModel.Hashing.makeSecureHashAlgorithm256(payloadData)
        let secureHash256 = OpalCryptoBoundaryModel.Hashing.makeSecureHash256(payloadData)
        let secureHash160 = OpalCryptoBoundaryModel.Hashing.makeSecureHash160(payloadData)
        let hmacSecureHashAlgorithm512 = OpalCryptoBoundaryModel.Hashing
            .makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(
                data: payloadData,
                key: Data(repeating: 0x0B, count: 16)
            )

        #expect(secureHashAlgorithm256.count == 32)
        #expect(secureHash256.count == 32)
        #expect(secureHash160.count == 20)
        #expect(hmacSecureHashAlgorithm512.count == 64)

        let base58Encoded = OpalCryptoBoundaryModel.Encoding.encodeBase58(payloadData)
        let base58Decoded = OpalCryptoBoundaryModel.Encoding.decodeBase58(base58Encoded)
        #expect(base58Decoded == payloadData)

        let base32FiveBitInput = Data([0, 1, 2, 3, 4, 5, 30, 31])
        let base32Encoded = OpalCryptoBoundaryModel.Encoding.encodeBase32(
            base32FiveBitInput,
            interpretedAsFiveBitValues: true
        )
        let base32Decoded = try OpalCryptoBoundaryModel.Encoding.decodeBase32(
            base32Encoded,
            interpretedAsFiveBitValues: true
        )
        #expect(base32Decoded == base32FiveBitInput)

        let checksumValue = OpalCryptoBoundaryModel.Encoding.computePolynomialModuloChecksum([1, 2, 3, 4, 5])
        #expect(checksumValue != 0)

        let derivedKey = try OpalCryptoBoundaryModel.KeyDerivation.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        let derivedKeyAgain = try OpalCryptoBoundaryModel.KeyDerivation.derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data("password".utf8),
            saltData: Data("salt".utf8),
            iterationCount: 16,
            derivedKeyLength: 32
        )
        #expect(derivedKey.count == 32)
        #expect(derivedKey == derivedKeyAgain)

        var largeUnsignedInteger = OpalCryptoBoundaryModel.Numeric.BigUnsignedInteger(256)
        largeUnsignedInteger.multiply(by: 16)
        #expect(!largeUnsignedInteger.isZero)
        #expect(largeUnsignedInteger.serialize().count > 0)

        let unsigned256 = try OpalCryptoBoundaryModel.Numeric.UInt256(
            data32Bytes: Data(repeating: 0x01, count: 32)
        )
        let unsigned512 = try OpalCryptoBoundaryModel.Numeric.UInt512(
            data64Bytes: Data(repeating: 0x02, count: 64)
        )
        let fullWidthProduct = unsigned256.multiplyFullWidth(by: unsigned256)

        #expect(unsigned256.data32Bytes.count == 32)
        #expect(unsigned512.data64Bytes.count == 64)
        #expect(fullWidthProduct.data64Bytes.count == 64)
    }

    @Test("Reject sign with invalid private key length through boundary error")
    func rejectSignWithInvalidPrivateKeyLengthThroughBoundaryError() {
        let messageData = Data("opal-ecdsa-message".utf8)
        let invalidPrivateKey = Data(repeating: 0x01, count: 31)

        do {
            _ = try OpalCryptoBoundaryModel.Signature.sign(
                messageData: messageData,
                privateKeyData: invalidPrivateKey,
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as OpalCryptoBoundaryModel.Signature.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key length through boundary error")
    func rejectVerifyWithInvalidPublicKeyLengthThroughBoundaryError() {
        do {
            _ = try OpalCryptoBoundaryModel.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 64),
                messageData: Data(repeating: 0xAB, count: 32),
                publicKeyData: Data(repeating: 0x02, count: 32),
                format: .schnorr
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCryptoBoundaryModel.Signature.Error {
            #expect(error == .invalidPublicKeyLength(expected: 33, actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key prefix through boundary error")
    func rejectVerifyWithInvalidPublicKeyPrefixThroughBoundaryError() {
        var publicKeyData = Data(repeating: 0x00, count: 33)
        publicKeyData[0] = 0x04

        do {
            _ = try OpalCryptoBoundaryModel.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 64),
                messageData: Data(repeating: 0xAB, count: 32),
                publicKeyData: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid public key prefix error.")
        } catch let error as OpalCryptoBoundaryModel.Signature.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x04))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr sign with invalid digest length through boundary error")
    func rejectSchnorrSignWithInvalidDigestLengthThroughBoundaryError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01

        do {
            _ = try OpalCryptoBoundaryModel.Signature.sign(
                messageData: Data(repeating: 0xAB, count: 31),
                privateKeyData: privateKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid digest length error.")
        } catch let error as OpalCryptoBoundaryModel.Signature.Error {
            #expect(error == .invalidDigestLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr verify with invalid signature length through boundary error")
    func rejectSchnorrVerifyWithInvalidSignatureLengthThroughBoundaryError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x03
        let digestData32Bytes = Data(repeating: 0xCD, count: 32)

        do {
            let publicKeyData = try OpalCryptoBoundaryModel.Signature.derivePublicKey(
                fromPrivateKeyData: privateKeyData
            )

            _ = try OpalCryptoBoundaryModel.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 63),
                messageData: digestData32Bytes,
                publicKeyData: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCryptoBoundaryModel.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
