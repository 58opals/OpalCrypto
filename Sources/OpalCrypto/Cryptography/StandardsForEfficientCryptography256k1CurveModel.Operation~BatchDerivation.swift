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

        let taskCount = batchDerivationTaskCount(
            totalCount: privateKeys32.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveCompressedPublicKeysSingleChunk(
                fromPrivateKeys32: privateKeys32,
                assumingValidPrivateKeys: assumingValidPrivateKeys
            )
        }
        let chunkSize = (privateKeys32.count + taskCount - 1) / taskCount
        return try await deriveCompressedPublicKeysInParallel(
            fromPrivateKeys32: privateKeys32,
            assumingValidPrivateKeys: assumingValidPrivateKeys,
            chunkSize: chunkSize
        )
    }
}

private extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static let minimumAutomaticParallelKeyCount = 512
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
            return min(processorCount, totalCount / minimumKeysPerTask)
        case .serial:
            return 1
        case .parallel:
            let targetTaskCount = max(2, (totalCount + minimumKeysPerTask - 1) / minimumKeysPerTask)
            return min(processorCount, totalCount, targetTaskCount)
        }
    }

    static func deriveCompressedPublicKeysInParallel(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool,
        chunkSize: Int
    ) async throws -> [Data] {
        let totalCount = privateKeys32.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: CompressedPublicKeyChunkResult.self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    return CompressedPublicKeyChunkResult(
                        chunkIndex: chunkIndex,
                        compressedPublicKeys: try deriveCompressedPublicKeysSingleChunk(
                            fromPrivateKeys32: privateKeys32,
                            startIndex: startIndex,
                            endIndex: endIndex,
                            assumingValidPrivateKeys: assumingValidPrivateKeys
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
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool
    ) throws -> [Data] {
        try deriveCompressedPublicKeysSingleChunk(
            fromPrivateKeys32: privateKeys32,
            startIndex: 0,
            endIndex: privateKeys32.count,
            assumingValidPrivateKeys: assumingValidPrivateKeys
        )
    }

    static func deriveCompressedPublicKeysSingleChunk(
        fromPrivateKeys32 privateKeys32: [Data],
        startIndex: Int,
        endIndex: Int,
        assumingValidPrivateKeys: Bool
    ) throws -> [Data] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(endIndex - startIndex)

        for index in startIndex..<endIndex {
            let privateKeyScalar = if assumingValidPrivateKeys {
                try parsePrivateKeyScalarUnchecked(privateKeys32[index], requireNonZero: true)
            } else {
                try parsePrivateKeyScalar(privateKeys32[index], requireNonZero: true)
            }
            jacobianPoints.append(ScalarMultiplicationModel.mulG(privateKeyScalar))
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
