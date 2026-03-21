// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchDerivation.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    internal static func deriveCompressedPublicKeys(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool = false
    ) async throws -> [Data] {
        try await deriveCompressedPublicKeys(
            fromPrivateKeys32: privateKeys32,
            assumingValidPrivateKeys: assumingValidPrivateKeys,
            executionMode: .automatic
        )
    }

    internal static func deriveCompressedPublicKeys(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool = false,
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode
    ) async throws -> [Data] {
        guard !privateKeys32.isEmpty else { return .init() }
        let privateKeyScalars = try parsePrivateKeyScalars(
            fromPrivateKeys32: privateKeys32,
            assumingValidPrivateKeys: assumingValidPrivateKeys
        )
        return try await deriveCompressedPublicKeys(
            fromPrivateKeyScalars: privateKeyScalars,
            executionMode: executionMode
        )
    }

    internal static func deriveCompressedPublicKeys(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode
    ) async throws -> [Data] {
        guard !privateKeyScalars.isEmpty else { return .init() }
        let taskCount = batchDerivationTaskCount(
            totalCount: privateKeyScalars.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveCompressedPublicKeysSingleChunk(
                fromPrivateKeyScalars: privateKeyScalars
            )
        }
        let chunkSize = (privateKeyScalars.count + taskCount - 1) / taskCount
        return try await deriveCompressedPublicKeysInParallel(
            fromPrivateKeyScalars: privateKeyScalars,
            chunkSize: chunkSize
        )
    }

    internal static func parsePrivateKeyScalars(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool
    ) throws -> [ScalarModel] {
        var privateKeyScalars: [ScalarModel] = .init()
        privateKeyScalars.reserveCapacity(privateKeys32.count)

        for privateKey32 in privateKeys32 {
            let privateKeyScalar = if assumingValidPrivateKeys {
                try parsePrivateKeyScalarUnchecked(privateKey32, requireNonZero: true)
            } else {
                try parsePrivateKeyScalar(privateKey32, requireNonZero: true)
            }
            privateKeyScalars.append(privateKeyScalar)
        }

        return privateKeyScalars
    }
}

private extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static let minimumAutomaticParallelKeyCount = 256
    static let minimumKeysPerTask = 256

    static func batchDerivationTaskCount(
        totalCount: Int,
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode
    ) -> Int {
        guard totalCount > 0 else { return 0 }

        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        switch executionMode {
        case .automatic:
            guard totalCount >= minimumAutomaticParallelKeyCount else {
                return 1
            }
            return parallelBatchDerivationTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        case .serial:
            return 1
        case .parallel:
            return parallelBatchDerivationTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        }
    }

    static func parallelBatchDerivationTaskCount(
        totalCount: Int,
        processorCount: Int
    ) -> Int {
        let targetTaskCount = max(2, (totalCount + minimumKeysPerTask - 1) / minimumKeysPerTask)
        return min(processorCount, targetTaskCount)
    }

    static func deriveCompressedPublicKeysInParallel(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        chunkSize: Int
    ) async throws -> [Data] {
        let totalCount = privateKeyScalars.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: CompressedPublicKeyChunkResult.self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    return CompressedPublicKeyChunkResult(
                        chunkIndex: chunkIndex,
                        compressedPublicKeys: try deriveCompressedPublicKeysSingleChunk(
                            fromPrivateKeyScalars: privateKeyScalars,
                            startIndex: startIndex,
                            endIndex: endIndex
                        )
                    )
                }
            }

            var chunkResults = Array<[Data]?>(repeating: nil, count: chunkCount)

            for try await chunkResult in group {
                chunkResults[chunkResult.chunkIndex] = chunkResult.compressedPublicKeys
            }

            var compressedPublicKeys: [Data] = .init()
            compressedPublicKeys.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                compressedPublicKeys.append(contentsOf: chunkResult)
            }
            return compressedPublicKeys
        }
    }

    static func deriveCompressedPublicKeysSingleChunk(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel]
    ) throws -> [Data] {
        try deriveCompressedPublicKeysSingleChunk(
            fromPrivateKeyScalars: privateKeyScalars,
            startIndex: 0,
            endIndex: privateKeyScalars.count
        )
    }

    static func deriveCompressedPublicKeysSingleChunk(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Data] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(endIndex - startIndex)

        for index in startIndex..<endIndex {
            jacobianPoints.append(ScalarMultiplicationModel.mulG(privateKeyScalars[index]))
        }

        let affinePoints = JacobianPointModel.convertBatchToAffine(jacobianPoints)
        var compressedPublicKeys: [Data] = .init()
        compressedPublicKeys.reserveCapacity(affinePoints.count)

        for affinePoint in affinePoints {
            guard let affinePoint else {
                throw Error.invalidDerivedPublicKey
            }
            compressedPublicKeys.append(encodePublicKey(affinePoint, format: .compressed))
        }

        return compressedPublicKeys
    }
}
