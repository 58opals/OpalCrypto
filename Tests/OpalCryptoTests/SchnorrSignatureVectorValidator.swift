import Foundation
import Testing
import OpalCrypto

@Suite("Schnorr signature vector validation")
struct SchnorrSignatureVectorValidator {
    @Test("Verify all pure Swift Schnorr vectors")
    func verifyAllPureSwiftSchnorrVectors() {
        for vector in TestVectors.all {
            let context = makeContext(for: vector)
            do {
                let signaturePayload = try vector.signature64
                let digest32 = try vector.message32
                let publicKey = try vector.publicKey

                let signature = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: signaturePayload)
                let verificationResult = try SchnorrSignatureModel.verify(
                    signature: signature,
                    digestData32Bytes: digest32,
                    publicKey: publicKey
                )

                #expect(
                    verificationResult == vector.expectedVerificationResult,
                    "\(context): expected \(vector.expectedVerificationResult) but got \(verificationResult)."
                )
            } catch {
                Issue.record("\(context): unexpected error: \(error).")
            }
        }
    }

    @Test("Reproduce secret-key vectors with deterministic BIP Schnorr nonce")
    func reproduceSecretKeyVectorsWithDeterministicBitcoinImprovementProposalSchnorrNonce() {
        let vectorsWithSecretKeys = TestVectors.all.filter { $0.secretKeyHex != nil }
        #expect(vectorsWithSecretKeys.count == 3, "Expected exactly 3 vectors with secret keys.")

        for vector in vectorsWithSecretKeys {
            let context = makeContext(for: vector)
            do {
                guard let secretKey32 = try vector.secretKey32 else {
                    Issue.record("\(context): expected secret key bytes but found nil.")
                    continue
                }

                let digest32 = try vector.message32
                let expectedSignature = try vector.signature64
                let publicKey = try vector.publicKey

                let generatedSignature = try SchnorrSignatureModel.sign(
                    digestData32Bytes: digest32,
                    privateKeyData32Bytes: secretKey32,
                    nonce: .bitcoinImprovementProposalSchnorrDeterministic
                )

                #expect(
                    generatedSignature.raw64ByteSignatureData == expectedSignature,
                    "\(context): generated signature does not match expected vector signature."
                )

                let verificationResult = try SchnorrSignatureModel.verify(
                    signature: generatedSignature,
                    digestData32Bytes: digest32,
                    publicKey: publicKey
                )
                #expect(verificationResult, "\(context): generated signature failed verification.")
            } catch {
                Issue.record("\(context): unexpected error: \(error).")
            }
        }
    }

    private func makeContext(for vector: TestVectors.SchnorrTestVector) -> String {
        if let comment = vector.comment, !comment.isEmpty {
            return "Vector \(vector.index) (\(comment))"
        }
        return "Vector \(vector.index)"
    }
}
