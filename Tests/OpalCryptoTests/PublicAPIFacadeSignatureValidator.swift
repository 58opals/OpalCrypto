import Foundation
import Testing
import OpalCrypto

@Suite("Public API facade signature validation")
struct PublicAPIFacadeSignatureValidator {
    @Test("Exercise ECDSA sign and verify through public facade")
    func exerciseEcdsaSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01
        let messageData = Data("opal-ecdsa-message".utf8)

        let publicKeyData = try OpalCryptoFacade.Signature.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )
        let signatureData = try OpalCryptoFacade.Signature.sign(
            messageData: messageData,
            privateKeyData: privateKeyData,
            format: .ecdsa(.der)
        )

        let isValid = try OpalCryptoFacade.Signature.verify(
            signatureData: signatureData,
            messageData: messageData,
            publicKeyData: publicKeyData,
            format: .ecdsa(.der)
        )
        #expect(isValid)
    }

    @Test("Exercise Schnorr deterministic sign and verify through public facade")
    func exerciseSchnorrDeterministicSignAndVerifyThroughPublicFacade() throws {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x02
        let digestData32Bytes = Data(repeating: 0xAB, count: 32)
        let publicKeyData = try OpalCryptoFacade.Signature.derivePublicKey(
            fromPrivateKeyData: privateKeyData
        )

        let signatureData = try OpalCryptoFacade.Signature.sign(
            messageData: digestData32Bytes,
            privateKeyData: privateKeyData,
            format: .schnorr,
            noncePolicy: .bitcoinImprovementProposalSchnorrDeterministic
        )

        let isValid = try OpalCryptoFacade.Signature.verify(
            signatureData: signatureData,
            messageData: digestData32Bytes,
            publicKeyData: publicKeyData,
            format: .schnorr
        )
        #expect(isValid)
    }

    @Test("Reject sign with invalid private key length through facade error")
    func rejectSignWithInvalidPrivateKeyLengthThroughFacadeError() {
        let messageData = Data("opal-ecdsa-message".utf8)
        let invalidPrivateKey = Data(repeating: 0x01, count: 31)

        do {
            _ = try OpalCryptoFacade.Signature.sign(
                messageData: messageData,
                privateKeyData: invalidPrivateKey,
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as OpalCryptoFacade.Signature.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key length through facade error")
    func rejectVerifyWithInvalidPublicKeyLengthThroughFacadeError() {
        do {
            _ = try OpalCryptoFacade.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 64),
                messageData: Data(repeating: 0xAB, count: 32),
                publicKeyData: Data(repeating: 0x02, count: 32),
                format: .schnorr
            )
            Issue.record("Expected invalid public key length error.")
        } catch let error as OpalCryptoFacade.Signature.Error {
            #expect(error == .invalidPublicKeyLength(expected: 33, actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject verify with invalid public key prefix through facade error")
    func rejectVerifyWithInvalidPublicKeyPrefixThroughFacadeError() {
        var publicKeyData = Data(repeating: 0x00, count: 33)
        publicKeyData[0] = 0x04

        do {
            _ = try OpalCryptoFacade.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 64),
                messageData: Data(repeating: 0xAB, count: 32),
                publicKeyData: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid public key prefix error.")
        } catch let error as OpalCryptoFacade.Signature.Error {
            #expect(error == .invalidPublicKeyPrefix(actual: 0x04))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr sign with invalid digest length through facade error")
    func rejectSchnorrSignWithInvalidDigestLengthThroughFacadeError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x01

        do {
            _ = try OpalCryptoFacade.Signature.sign(
                messageData: Data(repeating: 0xAB, count: 31),
                privateKeyData: privateKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid digest length error.")
        } catch let error as OpalCryptoFacade.Signature.Error {
            #expect(error == .invalidDigestLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject Schnorr verify with invalid signature length through facade error")
    func rejectSchnorrVerifyWithInvalidSignatureLengthThroughFacadeError() {
        var privateKeyData = Data(repeating: 0x00, count: 32)
        privateKeyData[31] = 0x03
        let digestData32Bytes = Data(repeating: 0xCD, count: 32)

        do {
            let publicKeyData = try OpalCryptoFacade.Signature.derivePublicKey(
                fromPrivateKeyData: privateKeyData
            )

            _ = try OpalCryptoFacade.Signature.verify(
                signatureData: Data(repeating: 0x00, count: 63),
                messageData: digestData32Bytes,
                publicKeyData: publicKeyData,
                format: .schnorr
            )
            Issue.record("Expected invalid signature length error.")
        } catch let error as OpalCryptoFacade.Signature.Error {
            #expect(error == .invalidSignatureLength(expected: 64, actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
