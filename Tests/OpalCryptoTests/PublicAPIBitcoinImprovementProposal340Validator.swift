// PublicAPIBitcoinImprovementProposal340Validator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API BIP340 signature validation")
struct PublicAPIBitcoinImprovementProposal340Validator {
    @Test("Sign the official BIP340 32-byte message vectors")
    func signOfficialThirtyTwoByteMessageVectors() throws {
        for vector in BitcoinImprovementProposal340VectorData.records {
            guard
                let secretKeyHexadecimal = vector.secretKeyHexadecimal,
                let auxiliaryRandomnessHexadecimal =
                    vector.auxiliaryRandomnessHexadecimal
            else {
                continue
            }
            let signingKey = try OpalCrypto.Secp256k1.SigningKey(
                rawRepresentation: Data(hexadecimal: secretKeyHexadecimal)
            )
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(hexadecimal: vector.digestHexadecimal)
            )
            let auxiliaryRandomness = try
                OpalCrypto.Signature.BIP340.AuxiliaryRandomness(
                    rawRepresentation: Data(
                        hexadecimal: auxiliaryRandomnessHexadecimal
                    )
                )
            let signature = try signingKey.signBIP340(
                digest: digest,
                auxiliaryRandomness: auxiliaryRandomness
            )
            let expectedPublicKey = try Data(
                hexadecimal: vector.publicKeyHexadecimal
            )
            let expectedSignature = try Data(
                hexadecimal: vector.signatureHexadecimal
            )

            #expect(
                signingKey.bip340VerificationKey.rawRepresentation
                    == expectedPublicKey,
                "Official BIP340 vector \(vector.index) public key"
            )
            #expect(
                signature.rawRepresentation
                    == expectedSignature,
                "Official BIP340 vector \(vector.index) signature"
            )
        }
    }

    @Test("Verify the official positive and negative BIP340 32-byte message vectors")
    func verifyOfficialPositiveAndNegativeThirtyTwoByteMessageVectors() throws {
        for vector in BitcoinImprovementProposal340VectorData.records {
            let verificationResult: Bool
            do {
                let verificationKey = try
                    OpalCrypto.Signature.BIP340.VerificationKey(
                        rawRepresentation: Data(
                            hexadecimal: vector.publicKeyHexadecimal
                        )
                    )
                let digest = try OpalCrypto.Signature.Digest(
                    rawRepresentation: Data(
                        hexadecimal: vector.digestHexadecimal
                    )
                )
                let signature = try OpalCrypto.Signature.BIP340(
                    rawRepresentation: Data(
                        hexadecimal: vector.signatureHexadecimal
                    )
                )
                verificationResult = signature.verify(
                    digest: digest,
                    verificationKey: verificationKey
                )
            } catch {
                verificationResult = false
            }
            #expect(
                verificationResult == vector.isValid,
                "Official BIP340 vector \(vector.index) verification"
            )
        }
    }

    @Test("Reject malformed BIP340 facade values")
    func rejectMalformedFacadeValues() {
        #expect(throws: OpalCrypto.Signature.BIP340.Error.self) {
            _ = try OpalCrypto.Signature.BIP340.VerificationKey(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        #expect(throws: OpalCrypto.Signature.BIP340.Error.self) {
            _ = try OpalCrypto.Signature.BIP340.AuxiliaryRandomness(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        #expect(throws: OpalCrypto.Signature.BIP340.Error.self) {
            _ = try OpalCrypto.Signature.BIP340(
                rawRepresentation: Data(repeating: 0, count: 63)
            )
        }
    }

    @Test("Redact BIP340 auxiliary randomness descriptions")
    func redactAuxiliaryRandomnessDescriptions() throws {
        let bytes = Data(repeating: 0xA5, count: 32)
        let auxiliaryRandomness = try
            OpalCrypto.Signature.BIP340.AuxiliaryRandomness(
                rawRepresentation: bytes
            )
        let secretHexadecimal = bytes
            .map { String(format: "%02x", $0) }
            .joined()

        #expect(String(describing: auxiliaryRandomness).contains("redacted"))
        #expect(String(reflecting: auxiliaryRandomness).contains("redacted"))
        #expect(
            !String(describing: auxiliaryRandomness)
                .contains(secretHexadecimal)
        )
        #expect(
            !String(reflecting: auxiliaryRandomness)
                .contains(secretHexadecimal)
        )
    }
}
