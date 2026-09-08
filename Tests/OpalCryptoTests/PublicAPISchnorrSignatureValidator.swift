// PublicAPISchnorrSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API Schnorr signature validation")
struct PublicAPISchnorrSignatureValidator {
    @Test("Default Schnorr signing matches the Bitcoin Cash Node RFC6979 vector")
    func matchDefaultSchnorrSigningWithBitcoinCashNodeVector() throws {
        // Bitcoin Cash Node `src/test/key_tests.cpp`, deterministic Schnorr
        // signing case for key1 and Hash("Very deterministic message").
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(
                hexadecimal:
                    "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747"
            )
        )
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(
                hexadecimal:
                    "5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a"
            )
        )
        let expectedSignature = try Data(
            hexadecimal:
                "2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d07175"
                + "71846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce"
        )

        let signature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey
        )

        #expect(signature.rawRepresentation == expectedSignature)
    }

    @Test("Exercise Bitcoin Cash deterministic Schnorr signing through public facade")
    func exerciseBitcoinCashDeterministicSchnorrSigningThroughPublicFacade() throws {
        let privateKey = try makePrivateKey(2)
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0xAB, count: 32)
        )
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bchDeterministic
        )

        #expect(try signature.verify(digest: digest, publicKey: publicKey))
    }

    @Test("Schnorr signing defaults match explicit Bitcoin Cash deterministic output")
    func matchSchnorrSigningDefaultsWithExplicitBitcoinCashDeterministicOutput() throws {
        let privateKey = try makePrivateKey(2)
        let signingKey = privateKey.makeSigningKey()
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0xCD, count: 32)
        )
        let explicitSignature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bchDeterministic
        )
        let defaultSignature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey
        )
        let signingKeySignature = try signingKey.signSchnorr(digest: digest)

        #expect(defaultSignature.rawRepresentation == explicitSignature.rawRepresentation)
        #expect(signingKeySignature.rawRepresentation == explicitSignature.rawRepresentation)
        #expect(try signingKeySignature.verify(digest: digest, publicKey: signingKey.publicKey))
        #expect(try signingKeySignature.verify(digest: digest, verificationKey: signingKey.verificationKey))
    }

    @Test("Reject Schnorr signature construction with non-canonical field and scalar components")
    func rejectSchnorrSignatureConstructionWithNonCanonicalFieldAndScalarComponents() throws {
        let fieldPrime = try Data(
            hexadecimal: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        )
        let curveOrder = try Data(
            hexadecimal: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        let one = Data(repeating: 0x00, count: 31) + Data([0x01])

        for invalidSignature in [fieldPrime + one, one + curveOrder] {
            do {
                _ = try OpalCrypto.Signature.Schnorr(rawRepresentation: invalidSignature)
                Issue.record("Expected invalid Schnorr signature rejection.")
            } catch let error as OpalCrypto.Signature.Error {
                #expect(error == .invalidSignature)
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    private func makePrivateKey(_ value: UInt8) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
