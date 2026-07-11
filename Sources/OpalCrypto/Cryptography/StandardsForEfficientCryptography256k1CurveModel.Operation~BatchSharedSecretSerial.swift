// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchSharedSecretSerial.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Data] {
        var sharedSecrets: [Data] = .init()
        sharedSecrets.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            try Task.checkCancellation()
            let verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: parsedPublicKeyModels[index]
            )
            sharedSecrets.append(
                try deriveSharedSecret(
                    scalarPlan: scalarPlan,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        try Task.checkCancellation()
        return sharedSecrets
    }

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Data] {
        var sharedSecrets: [Data] = .init()
        sharedSecrets.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            try Task.checkCancellation()
            let verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: publicKeys[index].parsedPublicKeyModel
            )
            sharedSecrets.append(
                try deriveSharedSecret(
                    scalarPlan: scalarPlan,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        try Task.checkCancellation()
        return sharedSecrets
    }

    static func deriveSharedSecret(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        verificationKeyModel: VerificationKeyModel
    ) throws -> Data {
        let sharedPoint = ScalarMultiplicationModel.multiplyWindowedDigits(
            primaryDigits: scalarPlan.primaryDigits,
            primaryTable: verificationKeyModel.oddMultiplesAffine,
            secondaryDigits: scalarPlan.secondaryDigits,
            secondaryTable: verificationKeyModel.endomorphismOddMultiplesAffine
        )
        guard let sharedAffine = sharedPoint.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return SecureHashAlgorithm256Model.hash(sharedAffine.encodeCompressed33())
    }
}
