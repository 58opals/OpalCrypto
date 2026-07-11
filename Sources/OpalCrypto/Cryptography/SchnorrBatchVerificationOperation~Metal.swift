// SchnorrBatchVerificationOperation~Metal.swift

extension SchnorrBatchVerificationOperation {
    static func executeUsingMetal(
        input: SchnorrBatchVerificationInput,
        initialCPUPreparationDuration: Duration?
    ) async throws -> SchnorrBatchVerificationExecutionResult {
        guard MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable else {
            throw MetalSchnorrBatchVerificationError.uncertifiedDevice
        }
        let clock = ContinuousClock()
        var preparationDuration = initialCPUPreparationDuration ?? .zero
        var executionDuration = Duration.zero
        var readbackDuration = Duration.zero
        var results: [Bool] = []
        results.reserveCapacity(input.recordCount)
        let chunkCount = max(
            1,
            (input.recordCount
                + MetalSchnorrBatchInputPreparationOperation.maximumRecordCount
                - 1)
                / MetalSchnorrBatchInputPreparationOperation.maximumRecordCount
        )

        switch input.keyInput {
        case .cached(let verificationKey):
            let preparationStart = clock.now
            let context = MetalSchnorrBatchInputPreparationOperation
                .makeCachedKeyContext(verificationKey: verificationKey)
            preparationDuration += preparationStart.duration(to: clock.now)
            for range in metalChunkRanges(recordCount: input.recordCount) {
                try Task.checkCancellation()
                let chunkPreparationStart = clock.now
                let metalInput = try await MetalSchnorrBatchInputPreparationOperation
                    .prepareCachedKeyInput(
                        signatures: input.signatures,
                        digests: input.digests,
                        range: range,
                        context: context
                    )
                preparationDuration += chunkPreparationStart.duration(to: clock.now)
                let chunkResult = try await MetalSchnorrBatchVerificationClient.shared
                    .verify(cachedKeyInput: metalInput)
                executionDuration += chunkResult.gpuExecutionDuration
                readbackDuration += chunkResult.readbackDuration
                results.append(contentsOf: chunkResult.results)
            }
        case .varying(let publicKeys):
            for range in metalChunkRanges(recordCount: input.recordCount) {
                try Task.checkCancellation()
                let chunkPreparationStart = clock.now
                let metalInput = try await MetalSchnorrBatchInputPreparationOperation
                    .prepareVaryingKeyInput(
                        signatures: input.signatures,
                        digests: input.digests,
                        publicKeys: publicKeys,
                        range: range
                    )
                preparationDuration += chunkPreparationStart.duration(to: clock.now)
                let chunkResult = try await MetalSchnorrBatchVerificationClient.shared
                    .verify(varyingKeyInput: metalInput)
                executionDuration += chunkResult.gpuExecutionDuration
                readbackDuration += chunkResult.readbackDuration
                results.append(contentsOf: chunkResult.results)
            }
        }

        guard results.count == input.recordCount else {
            throw MetalSchnorrBatchVerificationError.invalidOutput
        }
        return SchnorrBatchVerificationExecutionResult(
            results: results,
            backend: .metal,
            chunkCount: chunkCount,
            cpuPreparationDuration: preparationDuration,
            gpuExecutionDuration: executionDuration,
            readbackDuration: readbackDuration
        )
    }

    static func metalChunkRanges(recordCount: Int) -> [Range<Int>] {
        stride(
            from: 0,
            to: recordCount,
            by: MetalSchnorrBatchInputPreparationOperation.maximumRecordCount
        ).map { lowerBound in
            lowerBound..<min(
                recordCount,
                lowerBound
                    + MetalSchnorrBatchInputPreparationOperation.maximumRecordCount
            )
        }
    }
}
