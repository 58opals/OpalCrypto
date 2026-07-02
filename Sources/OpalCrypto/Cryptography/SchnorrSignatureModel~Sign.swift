// SchnorrSignatureModel~Sign.swift

import Foundation

internal extension SchnorrSignatureModel {
    static func sign(
        digestData32Bytes: Data,
        privateKeyData32Bytes: Data,
        nonce: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Signature {
        guard digestData32Bytes.count == 32 else {
            throw Error.invalidDigestLength(actual: digestData32Bytes.count)
        }
        guard privateKeyData32Bytes.count == 32 else {
            throw Error.invalidPrivateKeyLength(actual: privateKeyData32Bytes.count)
        }
        let privateKeyScalar: ScalarModel
        do {
            privateKeyScalar = try ScalarModel(data32: privateKeyData32Bytes, requireNonZero: true)
        } catch {
            throw Error.invalidPrivateKeyValue
        }
        let publicKeyPoint = ScalarMultiplicationModel.mulG(privateKeyScalar)
        guard let publicKeyAffine = publicKeyPoint.convertToAffine() else {
            throw Error.invalidPrivateKeyValue
        }
        return try sign(
            digestData32Bytes: digestData32Bytes,
            privateKeyScalar: privateKeyScalar,
            publicKeyAffine: publicKeyAffine,
            nonce: nonce
        )
    }

    static func sign(
        digestData32Bytes: Data,
        parsedPrivateKeyModel: ParsedPrivateKeyModel,
        nonce: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
    ) throws -> Signature {
        guard digestData32Bytes.count == 32 else {
            throw Error.invalidDigestLength(actual: digestData32Bytes.count)
        }
        return try sign(
            digestData32Bytes: digestData32Bytes,
            privateKeyScalar: parsedPrivateKeyModel.scalar,
            publicKeyAffine: parsedPrivateKeyModel.parsedPublicKeyModel.affinePoint,
            nonce: nonce
        )
    }

    private static func sign(
        digestData32Bytes: Data,
        privateKeyScalar: ScalarModel,
        publicKeyAffine: AffinePointModel,
        nonce: NonceGenerationPolicy
    ) throws -> Signature {
        var makeNextNonce: () throws -> ScalarModel
        switch nonce {
        case .requestForComments6979BitcoinCashDefault:
            var generator = try NonceGeneratorModel(privateKey: privateKeyScalar, digest32: digestData32Bytes)
            makeNextNonce = {
                try generator.makeNextScalar()
            }
        case .bitcoinImprovementProposalSchnorrDeterministic:
            var generator = try NonceGeneratorModel.BitcoinImprovementProposalSchnorrSignature(
                privateKey: privateKeyScalar,
                digest32: digestData32Bytes
            )
            makeNextNonce = {
                try generator.makeNextScalar()
            }
        case .systemRandom:
            makeNextNonce = {
                try NonceGeneratorModel.makeSystemRandomScalar()
            }
        }
        while true {
            let nonceScalar = try makeNextNonce()
            let noncePoint = ScalarMultiplicationModel.mulG(nonceScalar)
            let jacobiCandidate = noncePoint.Y.mul(noncePoint.Z)
            let adjustedNonceScalar: ScalarModel
            let adjustedNoncePoint: JacobianPointModel
            if jacobiCandidate.isQuadraticResidue {
                adjustedNonceScalar = nonceScalar
                adjustedNoncePoint = noncePoint
            } else {
                adjustedNonceScalar = nonceScalar.negateModN()
                adjustedNoncePoint = noncePoint.negate()
            }
            guard let adjustedNonceAffine = adjustedNoncePoint.convertToAffine() else {
                continue
            }
            let signatureRFieldElement = adjustedNonceAffine.x
            let challengeScalar = try ChallengeHashModel.makeChallengeScalar(
                digest32: digestData32Bytes,
                r: signatureRFieldElement,
                publicKey: publicKeyAffine
            )
            let product = challengeScalar.mulModN(privateKeyScalar)
            let signatureSScalar = adjustedNonceScalar.addModN(product)
            guard !signatureSScalar.isZero else {
                continue
            }
            return try Signature(
                r: signatureRFieldElement.data32Bytes,
                s: signatureSScalar.data32Bytes
            )
        }
    }
}
