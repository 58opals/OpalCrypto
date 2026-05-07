// InternalSignatureVerifierValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Internal signature verifier validation")
struct InternalSignatureVerifierValidator {
    @Test("Internal verifier accepts sliced compressed public-key payloads")
    func internalVerifierAcceptsSlicedCompressedPublicKeyPayloads() throws {
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([0x01])
        )
        let message = Data("opal-ecdsa-message".utf8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let slicedPublicKey = (Data([0xFF]) + publicKey.rawRepresentation).dropFirst()
        let signature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .raw
        )

        #expect(
            try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                signature: signature.rawRepresentation,
                message: message,
                publicKey: slicedPublicKey,
                format: .ecdsa(.raw)
            )
        )
    }

    @Test("Internal verifier preserves invalid compressed public-key length payloads")
    func internalVerifierPreservesInvalidCompressedPublicKeyLengthPayloads() {
        do {
            _ = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                signature: Data(repeating: 0x00, count: 64),
                message: Data("opal-ecdsa-message".utf8),
                publicKey: Data(repeating: 0x02, count: 32),
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid compressed public key length error.")
        } catch let EllipticCurveDigitalSignatureAlgorithmModel.Error
            .invalidCompressedPublicKeyLength(expected, actual) {
            #expect(expected == 33)
            #expect(actual == 32)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Internal verifier preserves invalid compressed public-key prefix payloads")
    func internalVerifierPreservesInvalidCompressedPublicKeyPrefixPayloads() {
        var publicKeyData = Data(repeating: 0x00, count: 33)
        publicKeyData[0] = 0x04

        do {
            _ = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                signature: Data(repeating: 0x00, count: 64),
                message: Data("opal-ecdsa-message".utf8),
                publicKey: publicKeyData,
                format: .ecdsa(.raw)
            )
            Issue.record("Expected invalid compressed public key prefix error.")
        } catch let EllipticCurveDigitalSignatureAlgorithmModel.Error
            .invalidCompressedPublicKeyPrefix(actual) {
            #expect(actual == 0x04)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
