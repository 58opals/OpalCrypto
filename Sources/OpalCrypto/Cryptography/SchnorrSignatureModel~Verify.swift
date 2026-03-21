// SchnorrSignatureModel~Verify.swift

import Foundation

internal extension SchnorrSignatureModel {
    static func verify(
        signature: Signature,
        digestData32Bytes: Data,
        publicKey: Data
    ) throws -> Bool {
        let verificationKeyModel: VerificationKeyModel
        do {
            verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .makeVerificationKey(publicKey: publicKey)
        } catch {
            return false
        }
        return try verify(
            signature: signature,
            digestData32Bytes: digestData32Bytes,
            verificationKeyModel: verificationKeyModel
        )
    }

    static func verify(
        signature: Signature,
        digestData32Bytes: Data,
        verificationKeyModel: VerificationKeyModel
    ) throws -> Bool {
        guard digestData32Bytes.count == 32 else {
            throw Error.invalidDigestLength(actual: digestData32Bytes.count)
        }
        let signatureRFieldElement: FieldElementModel
        do {
            signatureRFieldElement = try FieldElementModel(data32: signature.r)
        } catch {
            return false
        }
        let signatureSScalar: ScalarModel
        do {
            signatureSScalar = try ScalarModel(data32: signature.s)
        } catch {
            return false
        }
        let challengeScalar: ScalarModel
        do {
            challengeScalar = try ChallengeHashModel.makeChallengeScalar(
                digest32: digestData32Bytes,
                r: signatureRFieldElement,
                verificationKeyModel: verificationKeyModel
            )
        } catch {
            return false
        }
        let candidatePoint = ScalarMultiplicationModel.mulJointGeneratorAndVerificationKey(
            generatorScalar: signatureSScalar,
            verificationKeyScalar: challengeScalar.negateModN(),
            verificationKeyModel: verificationKeyModel
        )
        guard !candidatePoint.isInfinity else {
            return false
        }
        let zSquared = candidatePoint.Z.square()
        let expectedX = signatureRFieldElement.mul(zSquared)
        guard candidatePoint.X == expectedX else {
            return false
        }
        let jacobiCandidate = candidatePoint.Y.mul(candidatePoint.Z)
        guard jacobiCandidate.isQuadraticResidue else {
            return false
        }
        return true
    }
}
