// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchDerivation.swift

import Foundation

// Keep unsplit for batch-derivation auditability.

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
            return try encodeCompressedPublicKeys(
                fromJacobianPoints: derivePublicKeyJacobianPoints(
                    fromPrivateKeyScalars: privateKeyScalars
                )
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

    internal static func derivePublicKeyJacobianPoints(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel]
    ) -> [JacobianPointModel] {
        derivePublicKeyJacobianPoints(
            fromPrivateKeyScalars: privateKeyScalars,
            startIndex: 0,
            endIndex: privateKeyScalars.count
        )
    }

    internal static func encodeCompressedPublicKeys(
        fromJacobianPoints jacobianPoints: [JacobianPointModel]
    ) throws -> [Data] {
        encodeCompressedPublicKeysFromNonInfinityJacobianPoints(jacobianPoints)
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

    static func derivePublicKeyJacobianPointsInParallel(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        chunkSize: Int
    ) async throws -> [JacobianPointModel] {
        let totalCount = privateKeyScalars.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: JacobianPointChunkResult.self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    return JacobianPointChunkResult(
                        chunkIndex: chunkIndex,
                        jacobianPoints: derivePublicKeyJacobianPoints(
                            fromPrivateKeyScalars: privateKeyScalars,
                            startIndex: startIndex,
                            endIndex: endIndex
                        )
                    )
                }
            }

            var chunkResults = Array<[JacobianPointModel]?>(repeating: nil, count: chunkCount)

            for try await chunkResult in group {
                chunkResults[chunkResult.chunkIndex] = chunkResult.jacobianPoints
            }

            var jacobianPoints: [JacobianPointModel] = .init()
            jacobianPoints.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                jacobianPoints.append(contentsOf: chunkResult)
            }
            return jacobianPoints
        }
    }

    static func deriveCompressedPublicKeysInParallel(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        chunkSize: Int
    ) async throws -> [Data] {
        let totalCount = privateKeyScalars.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [Data]).self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    let jacobianPoints = derivePublicKeyJacobianPoints(
                        fromPrivateKeyScalars: privateKeyScalars,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    return (
                        chunkIndex,
                        try encodeCompressedPublicKeys(
                            fromJacobianPoints: jacobianPoints
                        )
                    )
                }
            }

            var chunkResults = Array<[Data]?>(repeating: nil, count: chunkCount)

            for try await (chunkIndex, compressedPublicKeys) in group {
                chunkResults[chunkIndex] = compressedPublicKeys
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

    static func derivePublicKeyJacobianPoints(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        startIndex: Int,
        endIndex: Int
    ) -> [JacobianPointModel] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(endIndex - startIndex)

        for index in startIndex..<endIndex {
            jacobianPoints.append(ScalarMultiplicationModel.mulG(privateKeyScalars[index]))
        }

        return jacobianPoints
    }

    static func encodeCompressedPublicKeysFromNonInfinityJacobianPoints(
        _ jacobianPoints: [JacobianPointModel]
    ) -> [Data] {
        let affinePoints = JacobianPointModel.convertNonInfinityBatchToAffine(
            jacobianPoints
        )
        var compressedPublicKeys: [Data] = .init()
        compressedPublicKeys.reserveCapacity(affinePoints.count)

        for affinePoint in affinePoints {
            compressedPublicKeys.append(affinePoint.encodeCompressed33())
        }

        return compressedPublicKeys
    }
}
