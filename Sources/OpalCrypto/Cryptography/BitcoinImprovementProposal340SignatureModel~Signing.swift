// BitcoinImprovementProposal340SignatureModel~Signing.swift

import Foundation

extension BitcoinImprovementProposal340SignatureModel {
    static func sign(
        digestData32Bytes: Data,
        privateKeyScalar: ScalarModel,
        auxiliaryRandomnessData32Bytes: Data
    ) throws -> (
        signatureRFieldElement: FieldElementModel,
        signatureSScalar: ScalarModel
    ) {
        precondition(digestData32Bytes.count == 32)
        precondition(!privateKeyScalar.isZero)
        precondition(auxiliaryRandomnessData32Bytes.count == 32)

        let publicPoint = HardenedScalarMultiplicationModel.multiply(
            privateKeyScalar,
            by: ScalarMultiplicationModel.generator
        )
        guard let publicAffinePoint = publicPoint.affinePoint else {
            throw Error.pointAtInfinity
        }
        let privateSigningScalar = publicAffinePoint.y.isOdd
            ? HardenedScalarArithmeticModel
                .negateModuloCurveOrder(privateKeyScalar)
            : privateKeyScalar
        let verificationKeyModel =
            BitcoinImprovementProposal340VerificationKeyModel(
                affinePoint: publicAffinePoint
            )

        let auxiliaryHash = makeTaggedHash(
            tag: auxiliaryTag,
            input: auxiliaryRandomnessData32Bytes
        )
        let maskedPrivateKey = makeExclusiveOrData(
            privateSigningScalar.data32Bytes,
            auxiliaryHash
        )
        var nonceInput = Data()
        nonceInput.reserveCapacity(96)
        nonceInput.append(maskedPrivateKey)
        nonceInput.append(
            verificationKeyModel.rawRepresentationData32Bytes
        )
        nonceInput.append(digestData32Bytes)
        let nonceScalar = HardenedScalarArithmeticModel
            .reduceData32BytesModuloCurveOrder(
                makeTaggedHash(tag: nonceTag, input: nonceInput)
            )
        guard !nonceScalar.isZero else {
            throw Error.nonceIsZero
        }

        let noncePoint = HardenedScalarMultiplicationModel.multiply(
            nonceScalar,
            by: ScalarMultiplicationModel.generator
        )
        guard let nonceAffinePoint = noncePoint.affinePoint else {
            throw Error.pointAtInfinity
        }
        let adjustedNonceScalar = nonceAffinePoint.y.isOdd
            ? HardenedScalarArithmeticModel
                .negateModuloCurveOrder(nonceScalar)
            : nonceScalar
        let challengeScalar = makeChallengeScalar(
            signatureRData32Bytes: nonceAffinePoint.x.data32Bytes,
            verificationKeyData32Bytes:
                verificationKeyModel.rawRepresentationData32Bytes,
            digestData32Bytes: digestData32Bytes
        )
        let challengeProduct = HardenedScalarArithmeticModel
            .multiplyModuloCurveOrder(
                challengeScalar,
                privateSigningScalar
            )
        let signatureScalar = HardenedScalarArithmeticModel.addModN(
            adjustedNonceScalar,
            challengeProduct
        )

        guard verify(
            signatureRFieldElement: nonceAffinePoint.x,
            signatureSScalar: signatureScalar,
            digestData32Bytes: digestData32Bytes,
            verificationKeyModel: verificationKeyModel
        ) else {
            throw Error.selfVerificationFailed
        }
        return (nonceAffinePoint.x, signatureScalar)
    }
}
