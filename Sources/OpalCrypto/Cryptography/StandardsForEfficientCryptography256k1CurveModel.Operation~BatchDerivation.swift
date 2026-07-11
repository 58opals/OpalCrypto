// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchDerivation.swift

import Foundation

// Line-count exception (performance-critical math kernel): Parsing,
// serial/parallel dispatch, ordered chunk collection, and affine conversion stay
// together so cancellation, ordering, and benchmark invariants are reviewed as
// one operation. Evidence: docs/performance-roadmap.md and
// PerformanceOptimizationBatchDerivationValidator. Owner: Opal Crypto
// maintainers. Revisit when profiling changes the execution-mode thresholds.

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
        try Task.checkCancellation()
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
        try await derivePublicKeys(
            fromPrivateKeyScalars: privateKeyScalars,
            executionMode: executionMode,
            makePublicKeys: encodeCompressedPublicKeys(fromJacobianPoints:)
        )
    }

    internal static func deriveParsedPublicKeys(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool = false,
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode = .automatic
    ) async throws -> [ParsedPublicKeyModel] {
        guard !privateKeys32.isEmpty else { return .init() }
        try Task.checkCancellation()
        let privateKeyScalars = try parsePrivateKeyScalars(
            fromPrivateKeys32: privateKeys32,
            assumingValidPrivateKeys: assumingValidPrivateKeys
        )
        return try await deriveParsedPublicKeys(
            fromPrivateKeyScalars: privateKeyScalars,
            executionMode: executionMode
        )
    }

    internal static func deriveParsedPublicKeys(
        fromValidatedPrivateKeys privateKeys: [OpalCrypto.Secp256k1.PrivateKey],
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode = .automatic
    ) async throws -> [ParsedPublicKeyModel] {
        guard !privateKeys.isEmpty else { return .init() }
        try Task.checkCancellation()
        let privateKeyScalars = try parsePrivateKeyScalars(
            fromValidatedPrivateKeys: privateKeys
        )
        return try await deriveParsedPublicKeys(
            fromPrivateKeyScalars: privateKeyScalars,
            executionMode: executionMode
        )
    }

    internal static func deriveParsedPublicKeys(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode
    ) async throws -> [ParsedPublicKeyModel] {
        try await derivePublicKeys(
            fromPrivateKeyScalars: privateKeyScalars,
            executionMode: executionMode
        ) { jacobianPoints in
            makeParsedPublicKeys(fromJacobianPoints: jacobianPoints)
        }
    }

    internal static func parsePrivateKeyScalars(
        fromPrivateKeys32 privateKeys32: [Data],
        assumingValidPrivateKeys: Bool
    ) throws -> [ScalarModel] {
        var privateKeyScalars: [ScalarModel] = .init()
        privateKeyScalars.reserveCapacity(privateKeys32.count)

        for (index, privateKey32) in privateKeys32.enumerated() {
            if index.isMultiple(of: batchDerivationParsingCancellationCheckInterval) {
                try Task.checkCancellation()
            }
            let privateKeyScalar = if assumingValidPrivateKeys {
                try parsePrivateKeyScalarUnchecked(privateKey32, requireNonZero: true)
            } else {
                try parsePrivateKeyScalar(privateKey32, requireNonZero: true)
            }
            privateKeyScalars.append(privateKeyScalar)
        }

        return privateKeyScalars
    }

    internal static func parsePrivateKeyScalars(
        fromValidatedPrivateKeys privateKeys: [OpalCrypto.Secp256k1.PrivateKey]
    ) throws -> [ScalarModel] {
        var privateKeyScalars: [ScalarModel] = .init()
        privateKeyScalars.reserveCapacity(privateKeys.count)

        for (index, privateKey) in privateKeys.enumerated() {
            if index.isMultiple(of: batchDerivationParsingCancellationCheckInterval) {
                try Task.checkCancellation()
            }
            privateKeyScalars.append(privateKey.scalarModel)
        }

        return privateKeyScalars
    }

    internal static func derivePublicKeyJacobianPoints(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel]
    ) -> [JacobianPointModel] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(privateKeyScalars.count)
        for privateKeyScalar in privateKeyScalars {
            jacobianPoints.append(ScalarMultiplicationModel.mulG(privateKeyScalar))
        }
        return jacobianPoints
    }

    internal static func encodeCompressedPublicKeys(
        fromJacobianPoints jacobianPoints: [JacobianPointModel]
    ) throws -> [Data] {
        encodeCompressedPublicKeysFromNonInfinityJacobianPoints(jacobianPoints)
    }

    internal static func makeParsedPublicKeys(
        fromJacobianPoints jacobianPoints: [JacobianPointModel]
    ) -> [ParsedPublicKeyModel] {
        makeParsedPublicKeysFromNonInfinityJacobianPoints(jacobianPoints)
    }
}

private extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static let minimumAutomaticParallelKeyCount = 256
    static let minimumKeysPerTask = 128
    static let minimumAutomaticParallelTaskCount = 4
    static let batchDerivationCancellationCheckInterval = 8
    static let batchDerivationParsingCancellationCheckInterval = 32

    static func derivePublicKeys<PublicKey: Sendable>(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        executionMode: CompressedPublicKeyBatchDerivationExecutionMode,
        makePublicKeys: @Sendable @escaping ([JacobianPointModel]) throws -> [PublicKey]
    ) async throws -> [PublicKey] {
        guard !privateKeyScalars.isEmpty else { return .init() }
        try Task.checkCancellation()
        let taskCount = batchDerivationTaskCount(
            totalCount: privateKeyScalars.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            let jacobianPoints = try derivePublicKeyJacobianPointsCheckingCancellation(
                fromPrivateKeyScalars: privateKeyScalars,
                startIndex: 0,
                endIndex: privateKeyScalars.count
            )
            try Task.checkCancellation()
            let publicKeys = try makePublicKeys(jacobianPoints)
            try Task.checkCancellation()
            return publicKeys
        }
        let chunkSize = (privateKeyScalars.count + taskCount - 1) / taskCount
        return try await derivePublicKeysInParallel(
            fromPrivateKeyScalars: privateKeyScalars,
            chunkSize: chunkSize,
            makePublicKeys: makePublicKeys
        )
    }

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
            if totalCount == minimumAutomaticParallelKeyCount {
                return min(processorCount, minimumAutomaticParallelTaskCount)
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

    static func derivePublicKeysInParallel<PublicKey: Sendable>(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        chunkSize: Int,
        makePublicKeys: @Sendable @escaping ([JacobianPointModel]) throws -> [PublicKey]
    ) async throws -> [PublicKey] {
        try Task.checkCancellation()
        let totalCount = privateKeyScalars.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [PublicKey]).self) { group in
            for chunkIndex in 0..<chunkCount {
                try Task.checkCancellation()
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    try Task.checkCancellation()
                    let jacobianPoints = try derivePublicKeyJacobianPointsCheckingCancellation(
                        fromPrivateKeyScalars: privateKeyScalars,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    try Task.checkCancellation()
                    let publicKeys = try makePublicKeys(jacobianPoints)
                    try Task.checkCancellation()
                    return (
                        chunkIndex,
                        publicKeys
                    )
                }
            }

            var chunkResults = Array<[PublicKey]?>(repeating: nil, count: chunkCount)

            for try await (chunkIndex, publicKeys) in group {
                try Task.checkCancellation()
                chunkResults[chunkIndex] = publicKeys
            }

            try Task.checkCancellation()
            var publicKeys: [PublicKey] = .init()
            publicKeys.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                publicKeys.append(contentsOf: chunkResult)
            }
            try Task.checkCancellation()
            return publicKeys
        }
    }

    static func derivePublicKeyJacobianPointsCheckingCancellation(
        fromPrivateKeyScalars privateKeyScalars: [ScalarModel],
        startIndex: Int,
        endIndex: Int
    ) throws -> [JacobianPointModel] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(endIndex - startIndex)

        for index in startIndex..<endIndex {
            if (index - startIndex).isMultiple(of: batchDerivationCancellationCheckInterval) {
                try Task.checkCancellation()
            }
            jacobianPoints.append(ScalarMultiplicationModel.mulG(privateKeyScalars[index]))
        }

        try Task.checkCancellation()
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

    static func makeParsedPublicKeysFromNonInfinityJacobianPoints(
        _ jacobianPoints: [JacobianPointModel]
    ) -> [ParsedPublicKeyModel] {
        let affinePoints = JacobianPointModel.convertNonInfinityBatchToAffine(
            jacobianPoints
        )
        var parsedPublicKeys: [ParsedPublicKeyModel] = .init()
        parsedPublicKeys.reserveCapacity(affinePoints.count)

        for affinePoint in affinePoints {
            parsedPublicKeys.append(ParsedPublicKeyModel(affinePoint: affinePoint))
        }

        return parsedPublicKeys
    }
}
