// PublicAPIBlindSignatureFlowValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API blind signature flow validation")
struct PublicAPIBlindSignatureFlowValidator {
    @Test("Blind Schnorr requests finalize into valid signatures")
    func blindSchnorrRequestsFinalizeIntoValidSignatures() async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(5)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digest = Data(repeating: 0xAB, count: 32)
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: digest,
                publicKey: publicKey
            )
        )
    }

    @Test("Blind signature finalization rejects tampered responses")
    func blindSignatureFinalizationRejectsTamperedResponses() async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(6)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x6C, count: 32)
        )
        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
        var tamperedResponse = response
        tamperedResponse[tamperedResponse.index(before: tamperedResponse.endIndex)] ^= 0x01

        do {
            _ = try request.finalize(responseScalar: tamperedResponse)
            Issue.record("Expected blind-signature verification failure.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .verificationFailed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind request finalization rejects non-canonical response scalars even when verification is disabled")
    func blindRequestFinalizationRejectsNonCanonicalResponseScalarsEvenWhenVerificationIsDisabled()
        async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(11)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0xB3, count: 32)
        )

        do {
            _ = try request.finalize(
                responseScalar: try Data(
                    hexadecimal: """
                    fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                    """
                ),
                verify: false
            )
            Issue.record("Expected malformed response-scalar rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .cryptographyFailure)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
        let signature = try request.finalize(responseScalar: response, verify: false)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: Data(repeating: 0xB3, count: 32),
                publicKey: publicKey
            )
        )
    }
}
