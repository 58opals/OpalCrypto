// StandardsForEfficientCryptography256k1CurveModel~Verify.swift

import Foundation

public extension StandardsForEfficientCryptography256k1CurveModel {
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
        let publicKeyPoint = try PublicKeyParserModel.parsePublicKey(publicKey)
        let signatureRScalar = try ScalarModel(data32: signature.r, requireNonZero: true)
        let signatureSScalar = try ScalarModel(data32: signature.s, requireNonZero: true)
        let digestScalar = try ScalarConversionModel.makeReducedScalarFromDigest(digestData32Bytes)
        let signatureSInverse: ScalarModel
        do {
            signatureSInverse = try signatureSScalar.invert()
        } catch {
            throw Error.invalidSignatureScalar
        }
        let u1 = digestScalar.mulModN(signatureSInverse)
        let u2 = signatureRScalar.mulModN(signatureSInverse)
        let u1Point = ScalarMultiplicationModel.mulG(u1)
        let u2Point = ScalarMultiplicationModel.mul(u2, publicKeyPoint)
        let candidatePoint = u1Point.add(u2Point)
        guard let candidateAffine = candidatePoint.convertToAffine() else {
            return false
        }
        guard let candidateScalar = try? ScalarConversionModel.makeScalarFromFieldElement(candidateAffine.x) else {
            return false
        }
        return candidateScalar == signatureRScalar
    }
    
    static func verify(
        distinguishedEncodingRulesEncodedSignature: Data,
        digestData32Bytes: Data,
        publicKey: Data
    ) throws -> Bool {
        let signature = try Signature(distinguishedEncodingRulesEncoded: distinguishedEncodingRulesEncodedSignature)
        return try verify(signature: signature, digestData32Bytes: digestData32Bytes, publicKey: publicKey)
    }
}
