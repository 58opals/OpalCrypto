// SchnorrSignatureModel~Verify.swift

import Foundation

internal extension SchnorrSignatureModel {
    static func verify(
        signature: Signature,
        digestData32Bytes: Data,
        publicKey: Data
    ) throws -> Bool {
        guard digestData32Bytes.count == 32 else {
            throw Error.invalidDigestLength(actual: digestData32Bytes.count)
        }
        guard publicKey.count == 33 || publicKey.count == 65 else {
            throw Error.invalidPublicKeyLength(actual: publicKey.count)
        }
        let publicKeyPoint: AffinePointModel
        do {
            publicKeyPoint = try PublicKeyParserModel.parsePublicKey(publicKey)
        } catch {
            return false
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
                publicKey: publicKeyPoint
            )
        } catch {
            return false
        }
        let sTimesGenerator = ScalarMultiplicationModel.mulG(signatureSScalar)
        let eTimesPublicKey = ScalarMultiplicationModel.mul(challengeScalar, publicKeyPoint)
        let candidatePoint = sTimesGenerator.add(eTimesPublicKey.negate())
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
