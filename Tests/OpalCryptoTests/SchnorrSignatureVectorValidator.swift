// SchnorrSignatureVectorValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Schnorr signature vector validation")
struct SchnorrSignatureVectorValidator {
    @Test("Verify pure Swift Schnorr vector", arguments: SchnorrVectorRepository.all)
    func verifyPureSwiftSchnorrVector(_ vector: SchnorrVectorRepository.SchnorrVectorData) throws {
        let context = makeContext(for: vector)
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
            verificationResult == vector.isVerificationExpected,
            "\(context): expected \(vector.isVerificationExpected) but got \(verificationResult)."
        )
    }

    @Test("Repository exposes secret-key Schnorr vectors")
    func repositoryExposesSecretKeySchnorrVectors() {
        #expect(!SchnorrVectorRepository.withSecretKeys.isEmpty)
    }

    @Test(
        "Reproduce secret-key vector with deterministic BIP Schnorr nonce",
        arguments: SchnorrVectorRepository.withSecretKeys
    )
    func reproduceSecretKeyVectorWithDeterministicBitcoinImprovementProposalSchnorrNonce(
        _ vector: SchnorrVectorRepository.SchnorrVectorData
    ) throws {
        let context = makeContext(for: vector)
        let secretKey32 = try vector.secretKey32
        let requiredSecretKey32 = try #require(secretKey32)
        let digest32 = try vector.message32
        let expectedSignature = try vector.signature64
        let publicKey = try vector.publicKey

        let generatedSignature = try SchnorrSignatureModel.sign(
            digestData32Bytes: digest32,
            privateKeyData32Bytes: requiredSecretKey32,
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
    }

    private func makeContext(for vector: SchnorrVectorRepository.SchnorrVectorData) -> String {
        if let comment = vector.comment, !comment.isEmpty {
            return "Vector \(vector.index) (\(comment))"
        }
        return "Vector \(vector.index)"
    }
}
