// StandardsForEfficientCryptography256k1CurveModel~Verify.swift

import Foundation

internal extension StandardsForEfficientCryptography256k1CurveModel {
    static func verify(
        signature: Signature,
        digestData32Bytes: Data,
        publicKey: Data
    ) throws -> Bool {
        let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .makeVerificationKey(publicKey: publicKey)
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
        let candidatePoint = ScalarMultiplicationModel.mulJointGeneratorAndVerificationKey(
            generatorScalar: u1,
            verificationKeyScalar: u2,
            verificationKeyModel: verificationKeyModel
        )
        guard let candidateX = candidatePoint.convertXToAffine() else {
            return false
        }
        guard let candidateScalar = try? ScalarConversionModel.makeScalarFromFieldElement(candidateX) else {
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

    static func verify(
        distinguishedEncodingRulesEncodedSignature: Data,
        digestData32Bytes: Data,
        verificationKeyModel: VerificationKeyModel
    ) throws -> Bool {
        let signature = try Signature(
            distinguishedEncodingRulesEncoded: distinguishedEncodingRulesEncodedSignature
        )
        return try verify(
            signature: signature,
            digestData32Bytes: digestData32Bytes,
            verificationKeyModel: verificationKeyModel
        )
    }
}
