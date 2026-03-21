// PerformanceBenchmarkSupportModel.swift

import Foundation

package enum PerformanceBenchmarkSupportModel {
    package static func constructParsedPublicKey(
        publicKey: Data
    ) throws -> Data {
        try StandardsForEfficientCryptography256k1CurveModel.Operation
            .makeParsedPublicKey(publicKey: publicKey)
            .compressedPublicKeyData
    }

    package static func constructParsedPrivateKey(
        privateKey: Data
    ) throws -> Data {
        try ParsedPrivateKeyModel(privateKeyData32Bytes: privateKey)
            .compressedPublicKeyData
    }

    package static func multiplyVerificationKey(
        scalarData32Bytes: Data,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Data {
        let scalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                scalarData32Bytes,
                requireNonZero: false
            )
        let point = ScalarMultiplicationModel.mul(
            scalar,
            verificationKey.verificationKeyModel
        )
        guard let affinePoint = point.convertToAffine() else {
            return Data()
        }
        return affinePoint.encodeCompressed33()
    }

    package static func jointMultiplyGeneratorAndVerificationKey(
        generatorScalarData32Bytes: Data,
        verificationKeyScalarData32Bytes: Data,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Data {
        let generatorScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                generatorScalarData32Bytes,
                requireNonZero: false
            )
        let verificationKeyScalar = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.parseTweakScalar(
                verificationKeyScalarData32Bytes,
                requireNonZero: false
            )
        let point = ScalarMultiplicationModel.mulJointGeneratorAndVerificationKey(
            generatorScalar: generatorScalar,
            verificationKeyScalar: verificationKeyScalar,
            verificationKeyModel: verificationKey.verificationKeyModel
        )
        guard let affinePoint = point.convertToAffine() else {
            return Data()
        }
        return affinePoint.encodeCompressed33()
    }

    package static func deriveCompressedPublicKeysSerial(
        from privateKeys: [Data]
    ) async throws -> [Data] {
        try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .serial
            )
    }

    package static func deriveCompressedPublicKeysParallel(
        from privateKeys: [Data]
    ) async throws -> [Data] {
        try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .parallel
            )
    }

    package static func deriveCompressedPublicKeysFromScalars(
        from privateKeys: [Data]
    ) async throws -> [Data] {
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        return try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveCompressedPublicKeys(
                fromPrivateKeyScalars: privateKeyScalars,
                executionMode: .automatic
            )
    }
}
