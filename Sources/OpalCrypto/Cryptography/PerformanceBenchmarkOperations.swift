// PerformanceBenchmarkOperations.swift

// Line-count exception: benchmark-only operations stay together so benchmark call sites share one package seam.

import Foundation

package enum PerformanceBenchmarkOperations {
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

    package static func makeBatchJacobianPointBuffer(
        from privateKeys: [Data]
    ) throws -> BatchJacobianPointBuffer {
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        return BatchJacobianPointBuffer(
            points: StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKeyJacobianPoints(
                    fromPrivateKeyScalars: privateKeyScalars
                )
        )
    }

    package static func multiplyBatchGeneratorScalars(
        from privateKeys: [Data]
    ) throws -> Int {
        let batchJacobianPointBuffer = try makeBatchJacobianPointBuffer(
            from: privateKeys
        )
        guard let firstPoint = batchJacobianPointBuffer.points.first else {
            return 0
        }
        return batchJacobianPointBuffer.points.count
            ^ Int(firstPoint.X.data32Bytes[0])
            ^ Int(firstPoint.Y.data32Bytes[0])
            ^ Int(firstPoint.Z.data32Bytes[0])
    }

    package static func convertBatchJacobianPointBufferToCompressedPublicKeys(
        _ batchJacobianPointBuffer: BatchJacobianPointBuffer
    ) throws -> [Data] {
        try StandardsForEfficientCryptography256k1CurveModel.Operation
            .encodeCompressedPublicKeys(
                fromJacobianPoints: batchJacobianPointBuffer.points
            )
    }

    package static func computeFieldSquareRoot(
        fieldElementData32Bytes: Data
    ) throws -> Data {
        let fieldElement = try FieldElementModel(data32: fieldElementData32Bytes)
        guard let squareRoot = fieldElement.sqrt() else {
            return Data()
        }
        return squareRoot.data32Bytes
    }

    package static func checkFieldQuadraticResidue(
        fieldElementData32Bytes: Data
    ) throws -> Bool {
        try FieldElementModel(data32: fieldElementData32Bytes).isQuadraticResidue
    }

    package static func invertScalar(
        scalarData32Bytes: Data
    ) throws -> Data {
        try ScalarModel(data32: scalarData32Bytes, requireNonZero: true)
            .invert()
            .data32Bytes
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

    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        return try SchnorrBatchVerificationOperation.verifySerialUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                verificationKey: verificationKey
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeys.count
        )
        return try SchnorrBatchVerificationOperation
            .verifyPreparedKeysSerialUsingCPU(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeyRawRepresentations: [Data]
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeyRawRepresentations.count
        )
        let publicKeys = try verificationKeyRawRepresentations.map {
            try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: $0)
        }
        return try SchnorrBatchVerificationOperation.verifySerialUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                publicKeys: publicKeys
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        return try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                verificationKey: verificationKey
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeys.count
        )
        return try await SchnorrBatchVerificationOperation
            .verifyPreparedKeysUsingCPU(
                signatures: signatures,
                digests: digests,
                verificationKeys: verificationKeys
            )
            .map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeyRawRepresentations: [Data]
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeyRawRepresentations.count
        )
        let publicKeys = try verificationKeyRawRepresentations.map {
            try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: $0)
        }
        return try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                publicKeys: publicKeys
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func deriveSharedSecretsSerial(
        privateKey: Data,
        publicKeys: [Data]
    ) async throws -> [Data] {
        try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveSharedSecrets(
                privateKeyData32Bytes: privateKey,
                publicKeys: publicKeys,
                executionMode: .serial
            )
    }

    package static func deriveSharedSecretsParallel(
        privateKey: Data,
        publicKeys: [Data]
    ) async throws -> [Data] {
        try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveSharedSecrets(
                privateKeyData32Bytes: privateKey,
                publicKeys: publicKeys,
                executionMode: .parallel
            )
    }

    private static func validateSchnorrBatchInputCounts(
        signatureCount: Int,
        digestCount: Int,
        verificationKeyCount: Int? = nil
    ) throws {
        guard signatureCount == digestCount,
              verificationKeyCount == nil || verificationKeyCount == signatureCount else {
            throw Error.mismatchedSchnorrBatchInputCounts(
                signatureCount: signatureCount,
                digestCount: digestCount,
                verificationKeyCount: verificationKeyCount
            )
        }
    }

}
