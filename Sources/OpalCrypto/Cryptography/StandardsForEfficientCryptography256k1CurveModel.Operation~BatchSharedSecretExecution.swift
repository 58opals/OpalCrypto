// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchSharedSecretExecution.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static let minimumAutomaticParallelSharedSecretCount = 256
    static let minimumSharedSecretsPerTask = 128
    static let minimumAutomaticParallelSharedSecretTaskCount = 4
    static let sharedSecretParsingCancellationCheckInterval = 32

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) async throws -> [Data] {
        try Task.checkCancellation()
        let taskCount = sharedSecretBatchTaskCount(
            totalCount: parsedPublicKeyModels.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveSharedSecrets(
                scalarPlan: scalarPlan,
                parsedPublicKeyModels: parsedPublicKeyModels,
                startIndex: 0,
                endIndex: parsedPublicKeyModels.count
            )
        }
        let chunkSize = (parsedPublicKeyModels.count + taskCount - 1) / taskCount
        return try await deriveSharedSecretsInParallel(
            scalarPlan: scalarPlan,
            parsedPublicKeyModels: parsedPublicKeyModels,
            chunkSize: chunkSize
        )
    }

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) async throws -> [Data] {
        try Task.checkCancellation()
        let taskCount = sharedSecretBatchTaskCount(
            totalCount: publicKeys.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveSharedSecrets(
                scalarPlan: scalarPlan,
                publicKeys: publicKeys,
                startIndex: 0,
                endIndex: publicKeys.count
            )
        }
        let chunkSize = (publicKeys.count + taskCount - 1) / taskCount
        return try await deriveSharedSecretsInParallel(
            scalarPlan: scalarPlan,
            publicKeys: publicKeys,
            chunkSize: chunkSize
        )
    }

    static func sharedSecretBatchTaskCount(
        totalCount: Int,
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) -> Int {
        guard totalCount > 0 else { return 0 }

        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        switch executionMode {
        case .automatic:
            guard totalCount >= minimumAutomaticParallelSharedSecretCount else {
                return 1
            }
            if totalCount == minimumAutomaticParallelSharedSecretCount {
                return min(processorCount, minimumAutomaticParallelSharedSecretTaskCount)
            }
            return parallelSharedSecretBatchTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        case .serial:
            return 1
        case .parallel:
            return parallelSharedSecretBatchTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        }
    }

    static func parallelSharedSecretBatchTaskCount(
        totalCount: Int,
        processorCount: Int
    ) -> Int {
        let targetTaskCount = max(
            2,
            (totalCount + minimumSharedSecretsPerTask - 1) / minimumSharedSecretsPerTask
        )
        return min(processorCount, targetTaskCount)
    }
}
