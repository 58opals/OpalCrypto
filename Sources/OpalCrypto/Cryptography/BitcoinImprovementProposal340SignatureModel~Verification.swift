// BitcoinImprovementProposal340SignatureModel~Verification.swift

import Foundation

extension BitcoinImprovementProposal340SignatureModel {
    static func verify(
        signatureRFieldElement: FieldElementModel,
        signatureSScalar: ScalarModel,
        digestData32Bytes: Data,
        verificationKeyModel:
            BitcoinImprovementProposal340VerificationKeyModel
    ) -> Bool {
        precondition(digestData32Bytes.count == 32)
        let challengeScalar = makeChallengeScalar(
            signatureRData32Bytes: signatureRFieldElement.data32Bytes,
            verificationKeyData32Bytes:
                verificationKeyModel.rawRepresentationData32Bytes,
            digestData32Bytes: digestData32Bytes
        )
        let candidatePoint = ScalarMultiplicationModel
            .mulJointGeneratorAndVerificationKey(
                generatorScalar: signatureSScalar,
                verificationKeyScalar:
                    HardenedScalarArithmeticModel
                        .negateModuloCurveOrder(challengeScalar),
                verificationKeyModel:
                    verificationKeyModel.verificationKeyModel
            )
        guard let candidateAffinePoint = candidatePoint.convertToAffine() else {
            return false
        }
        guard !candidateAffinePoint.y.isOdd else {
            return false
        }
        return candidateAffinePoint.x == signatureRFieldElement
    }
}
