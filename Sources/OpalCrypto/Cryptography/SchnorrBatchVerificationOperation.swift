// SchnorrBatchVerificationOperation.swift

import Foundation

enum SchnorrBatchVerificationOperation {
    private static let minimumRecordCountPerTask = 128
    private static let cancellationCheckStride = 32

    static func verifyUsingCPU(
        input: SchnorrBatchVerificationInput
    ) async throws -> [Bool] {
        try Task.checkCancellation()
        switch input.keyInput {
        case .cached(let verificationKey):
            return try await verifyCachedKeyUsingCPU(
                input: input,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
        case .varying(let publicKeys):
            if let verificationKeyModel = makeUniformVerificationKeyModel(
                publicKeys: publicKeys
            ) {
                return try await verifyCachedKeyUsingCPU(
                    input: input,
                    verificationKeyModel: verificationKeyModel
                )
            }
            return try await verifyVaryingKeysUsingCPU(
                input: input,
                publicKeys: publicKeys
            )
        }
    }

    static func verifySerialUsingCPU(
        input: SchnorrBatchVerificationInput
    ) throws -> [Bool] {
        try Task.checkCancellation()
        switch input.keyInput {
        case .cached(let verificationKey):
            return try verifyCachedKeyRange(
                input: input,
                startIndex: 0,
                endIndex: input.recordCount,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
        case .varying(let publicKeys):
            if let verificationKeyModel = makeUniformVerificationKeyModel(
                publicKeys: publicKeys
            ) {
                return try verifyCachedKeyRange(
                    input: input,
                    startIndex: 0,
                    endIndex: input.recordCount,
                    verificationKeyModel: verificationKeyModel
                )
            }
            return try verifyVaryingKeyRange(
                input: input,
                publicKeys: publicKeys,
                startIndex: 0,
                endIndex: input.recordCount
            )
        }
    }

    private static func verifyCachedKeyUsingCPU(
        input: SchnorrBatchVerificationInput,
        verificationKeyModel: VerificationKeyModel
    ) async throws -> [Bool] {
        try await verifyInParallel(
            recordCount: input.recordCount
        ) { startIndex, endIndex in
            try verifyCachedKeyRange(
                input: input,
                startIndex: startIndex,
                endIndex: endIndex,
                verificationKeyModel: verificationKeyModel
            )
        }
    }

    private static func verifyVaryingKeysUsingCPU(
        input: SchnorrBatchVerificationInput,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey]
    ) async throws -> [Bool] {
        try await verifyInParallel(
            recordCount: input.recordCount
        ) { startIndex, endIndex in
            try verifyVaryingKeyRange(
                input: input,
                publicKeys: publicKeys,
                startIndex: startIndex,
                endIndex: endIndex
            )
        }
    }

    private static func verifyCachedKeyRange(
        input: SchnorrBatchVerificationInput,
        startIndex: Int,
        endIndex: Int,
        verificationKeyModel: VerificationKeyModel
    ) throws -> [Bool] {
        var results: [Bool] = []
        results.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            try checkCancellation(index: index, startIndex: startIndex)
            results.append(
                try SchnorrSignatureModel.verify(
                    signature: input.signatures[index].signatureModel,
                    digestData32Bytes: input.digests[index].rawRepresentation,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        return results
    }

    private static func verifyVaryingKeyRange(
        input: SchnorrBatchVerificationInput,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Bool] {
        var results: [Bool] = []
        results.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            try checkCancellation(index: index, startIndex: startIndex)
            let verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: publicKeys[index].parsedPublicKeyModel
            )
            results.append(
                try SchnorrSignatureModel.verify(
                    signature: input.signatures[index].signatureModel,
                    digestData32Bytes: input.digests[index].rawRepresentation,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        return results
    }

    private static func checkCancellation(
        index: Int,
        startIndex: Int
    ) throws {
        guard (index - startIndex).isMultiple(of: cancellationCheckStride) else {
            return
        }
        try Task.checkCancellation()
    }

    static func verifyInParallel(
        recordCount: Int,
        operation: @Sendable @escaping (Int, Int) throws -> [Bool]
    ) async throws -> [Bool] {
        let taskCount = cpuTaskCount(recordCount: recordCount)
        guard taskCount >= 2 else {
            return try operation(0, recordCount)
        }

        let baseChunkSize = recordCount / taskCount
        let remainder = recordCount % taskCount
        return try await withThrowingTaskGroup(of: (Int, [Bool]).self) { group in
            for taskIndex in 0..<taskCount {
                let startIndex = taskIndex * baseChunkSize + min(taskIndex, remainder)
                let endIndex = startIndex + baseChunkSize + (taskIndex < remainder ? 1 : 0)
                group.addTask {
                    (startIndex, try operation(startIndex, endIndex))
                }
            }

            var orderedResults = [Bool](repeating: false, count: recordCount)
            for try await (startIndex, chunkResults) in group {
                for (offset, result) in chunkResults.enumerated() {
                    orderedResults[startIndex + offset] = result
                }
            }
            return orderedResults
        }
    }

    static func cpuTaskCount(recordCount: Int) -> Int {
        guard recordCount > 0 else {
            return 0
        }
        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        return min(
            processorCount,
            max(1, recordCount / minimumRecordCountPerTask)
        )
    }

    static func makeUniformVerificationKeyModel(
        publicKeys: [OpalCrypto.Secp256k1.PublicKey]
    ) -> VerificationKeyModel? {
        guard let firstPublicKey = publicKeys.first,
              publicKeys.dropFirst().allSatisfy({ $0 == firstPublicKey })
        else {
            return nil
        }
        return VerificationKeyModel(
            parsedPublicKeyModel: firstPublicKey.parsedPublicKeyModel
        )
    }
}
