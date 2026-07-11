// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchSharedSecret.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func deriveSharedSecrets(
        privateKeyData32Bytes: Data,
        publicKeys: [Data],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !publicKeys.isEmpty else { return .init() }
        try Task.checkCancellation()
        var parsedPublicKeys: [ParsedPublicKeyModel] = .init()
        parsedPublicKeys.reserveCapacity(publicKeys.count)
        for (index, publicKey) in publicKeys.enumerated() {
            if index.isMultiple(of: sharedSecretParsingCancellationCheckInterval) {
                try Task.checkCancellation()
            }
            parsedPublicKeys.append(
                ParsedPublicKeyModel(
                    affinePoint: try parsePublicKeyAffine(publicKey)
                )
            )
        }
        return try await deriveSharedSecrets(
            privateKeyData32Bytes: privateKeyData32Bytes,
            parsedPublicKeyModels: parsedPublicKeys,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecrets(
        privateKeyData32Bytes: Data,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !parsedPublicKeyModels.isEmpty else { return .init() }
        try Task.checkCancellation()
        let privateKeyScalar = try parsePrivateKeyScalar(
            privateKeyData32Bytes,
            requireNonZero: true
        )
        let scalarPlan = SharedSecretScalarMultiplicationPlan(
            privateKeyScalar: privateKeyScalar
        )
        return try await deriveSharedSecrets(
            scalarPlan: scalarPlan,
            parsedPublicKeyModels: parsedPublicKeyModels,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecrets(
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !publicKeys.isEmpty else { return .init() }
        try Task.checkCancellation()
        let scalarPlan = SharedSecretScalarMultiplicationPlan(
            privateKeyScalar: privateKey.scalarModel
        )
        return try await deriveSharedSecrets(
            scalarPlan: scalarPlan,
            publicKeys: publicKeys,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecret(
        privateKeyScalar: ScalarModel,
        publicKeyAffine: AffinePointModel
    ) throws -> Data {
        try deriveSharedSecret(
            scalarPlan: SharedSecretScalarMultiplicationPlan(privateKeyScalar: privateKeyScalar),
            verificationKeyModel: VerificationKeyModel(affinePoint: publicKeyAffine)
        )
    }
}
