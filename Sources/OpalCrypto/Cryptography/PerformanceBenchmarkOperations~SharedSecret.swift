// PerformanceBenchmarkOperations~SharedSecret.swift

import Foundation

extension PerformanceBenchmarkOperations {
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
}
