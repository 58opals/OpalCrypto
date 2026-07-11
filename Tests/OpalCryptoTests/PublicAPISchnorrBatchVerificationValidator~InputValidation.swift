// PublicAPISchnorrBatchVerificationValidator~InputValidation.swift

import OpalCrypto
import Testing

extension PublicAPISchnorrBatchVerificationValidator {
    @Test("Reject mismatched signature and digest counts before public-key counts")
    func rejectSignatureAndDigestCountMismatchFirst() throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(341).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("public-mismatched-records")
        let expectedError = OpalCrypto.Signature.Schnorr.VerificationBatch.Error
            .mismatchedSignatureAndDigestCounts(signatures: 0, digests: 1)

        do {
            _ = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: [],
                digests: [digest],
                verificationKey: signingKey.verificationKey
            )
            Issue.record("Expected cached-key input count rejection.")
        } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            #expect(error == expectedError)
        }

        do {
            _ = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: [],
                digests: [digest],
                publicKeys: [signingKey.publicKey]
            )
            Issue.record("Expected varying-key record count rejection.")
        } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            #expect(error == expectedError)
        }
    }

    @Test("Reject public-key counts that do not match the record count")
    func rejectMismatchedPublicKeyCount() throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(351).makeSigningKey()
        let expectedError = OpalCrypto.Signature.Schnorr.VerificationBatch.Error
            .mismatchedPublicKeyCount(expected: 0, actual: 1)

        do {
            _ = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: [],
                digests: [],
                publicKeys: [signingKey.publicKey]
            )
            Issue.record("Expected public-key input count rejection.")
        } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            #expect(error == expectedError)
        }
    }
}
