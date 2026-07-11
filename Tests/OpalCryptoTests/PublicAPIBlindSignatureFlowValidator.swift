// PublicAPIBlindSignatureFlowValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API blind signature flow validation")
struct PublicAPIBlindSignatureFlowValidator {
    @Test("Blind Schnorr requests finalize into valid signatures")
    func blindSchnorrRequestsFinalizeIntoValidSignatures() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(5)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digest = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0xAB, count: 32))
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let response = try await signer.signOnce(privateKey: privateKey, requestScalar: request.scalar)
        let signature = try request.finalize(responseScalar: response)
        let unverifiedSignature = try request.finalizeWithoutVerification(responseScalar: response)
        let legacyUnverifiedSignature = try request.finalize(responseScalar: response, verify: false)

        #expect(try signature.verify(digest: digest, publicKey: publicKey))
        #expect(unverifiedSignature == signature)
        #expect(legacyUnverifiedSignature == signature)
    }

    @Test("Blind signature finalization rejects tampered responses")
    func blindSignatureFinalizationRejectsTamperedResponses() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(6)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digest = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0x6C, count: 32))
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
        var tamperedResponseData = response.rawRepresentation
        tamperedResponseData[tamperedResponseData.index(before: tamperedResponseData.endIndex)] ^= 0x01
        let tamperedResponse = try OpalCrypto.Secp256k1.Scalar(
            rawRepresentation: tamperedResponseData
        )

        do {
            _ = try request.finalize(responseScalar: tamperedResponse)
            Issue.record("Expected blind-signature verification failure.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .verificationFailed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind response scalar construction rejects non-canonical scalars")
    func blindResponseScalarConstructionRejectsNonCanonicalScalars() throws {
        do {
            _ = try OpalCrypto.Secp256k1.Scalar(
                rawRepresentation: Data(
                    hexadecimal: """
                    fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                    """
                )
            )
            Issue.record("Expected malformed response-scalar rejection.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidTweak)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind request finalization rejects zero signature scalars even when verification is disabled")
    func blindRequestFinalizationRejectsZeroSignatureScalarsEvenWhenVerificationIsDisabled() throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(12)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digest = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0xC4, count: 32))
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let cancelingResponse = OpalCrypto.Secp256k1.Scalar(
            scalarModel: request.requestState.blindingScalarA.negateModN()
        )

        do {
            _ = try request.finalizeWithoutVerification(responseScalar: cancelingResponse)
            Issue.record("Expected zero signature-scalar rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .verificationFailed)
        } catch {
            Issue.record("Unexpected error type for zero signature scalar: \(error)")
        }
    }
}
