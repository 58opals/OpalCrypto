// MetalSchnorrBatchVerificationClient~Execution.swift

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal

extension MetalSchnorrBatchVerificationClient {
    func verify(
        cachedKeyInput input: MetalSchnorrCachedKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        guard input.recordCount > 0 else { return .empty }
        try await acquireExecution()
        defer { releaseExecution() }
        try Task.checkCancellation()
        guard !isQuarantined else {
            throw MetalSchnorrBatchVerificationError.selfTestFailed
        }
        try initializeRuntimeIfNeeded()
        try await performSelfTestIfNeeded()
        return try await execute(cachedKeyInput: input)
    }

    func verify(
        varyingKeyInput input: MetalSchnorrVaryingKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        guard input.recordCount > 0 else { return .empty }
        try await acquireExecution()
        defer { releaseExecution() }
        try Task.checkCancellation()
        guard !isQuarantined else {
            throw MetalSchnorrBatchVerificationError.selfTestFailed
        }
        try initializeRuntimeIfNeeded()
        try await performSelfTestIfNeeded()
        return try await execute(varyingKeyInput: input)
    }

    func execute(
        cachedKeyInput input: MetalSchnorrCachedKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        guard let commandQueue, let pipeline = cachedKeyPipeline, let countBuffer else {
            throw MetalSchnorrBatchVerificationError.unavailable
        }
        let inputByteCount = input.signatureXWords.count * MemoryLayout<UInt32>.stride
        let digitByteCount = input.packedDigits.count * MemoryLayout<Int8>.stride
        let outputByteCount = input.recordCount * MemoryLayout<UInt32>.stride
        let inputBuffer = try ensureBuffer(
            self.inputBuffer,
            minimumByteCount: inputByteCount
        )
        self.inputBuffer = inputBuffer
        let digitBuffer = try ensureBuffer(
            self.digitBuffer,
            minimumByteCount: digitByteCount
        )
        self.digitBuffer = digitBuffer
        let outputBuffer = try ensureBuffer(
            self.outputBuffer,
            minimumByteCount: outputByteCount
        )
        self.outputBuffer = outputBuffer
        let tableBuffer = try cacheCachedKeyTable(
            identifier: input.tableIdentifier,
            words: input.tableWords
        )
        copy(input.signatureXWords, byteCount: inputByteCount, to: inputBuffer)
        copy(input.packedDigits, byteCount: digitByteCount, to: digitBuffer)
        // SAFETY: Runtime initialization allocates this actor-owned shared
        // buffer with exactly one UInt32 of aligned storage.
        countBuffer.contents().assumingMemoryBound(to: UInt32.self).pointee
            = UInt32(input.recordCount)

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw MetalSchnorrBatchVerificationError.commandEncodingFailed
        }
        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.setBuffer(tableBuffer, offset: 0, index: 3)
        encoder.setBuffer(digitBuffer, offset: 0, index: 4)
        encoder.dispatchThreads(
            MTLSize(width: input.recordCount, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(
                width: Self.resolveThreadgroupWidth(pipeline: pipeline),
                height: 1,
                depth: 1
            )
        )
        encoder.endEncoding()
        let clock = ContinuousClock()
        let executionStart = clock.now
        try await commitAndAwait(commandBuffer)
        let gpuExecutionDuration = executionStart.duration(to: clock.now)
        let readbackStart = clock.now
        let results = try readResults(from: outputBuffer, count: input.recordCount)
        return MetalSchnorrBatchVerificationResult(
            results: results,
            gpuExecutionDuration: gpuExecutionDuration,
            readbackDuration: readbackStart.duration(to: clock.now)
        )
    }

    func execute(
        varyingKeyInput input: MetalSchnorrVaryingKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        guard let commandQueue, let pipeline = varyingKeyPipeline, let countBuffer else {
            throw MetalSchnorrBatchVerificationError.unavailable
        }
        let inputByteCount = input.signatureXWords.count * MemoryLayout<UInt32>.stride
        let digitByteCount = input.packedDigits.count * MemoryLayout<Int8>.stride
        let outputByteCount = input.recordCount * MemoryLayout<UInt32>.stride
        let tableByteCount = input.varyingVerificationKeyTableWords.count
            * MemoryLayout<UInt32>.stride
        let inputBuffer = try ensureBuffer(
            self.inputBuffer,
            minimumByteCount: inputByteCount
        )
        self.inputBuffer = inputBuffer
        let digitBuffer = try ensureBuffer(
            self.digitBuffer,
            minimumByteCount: digitByteCount
        )
        self.digitBuffer = digitBuffer
        let outputBuffer = try ensureBuffer(
            self.outputBuffer,
            minimumByteCount: outputByteCount
        )
        self.outputBuffer = outputBuffer
        let sharedTableBuffer = try cacheSharedGeneratorTable(
            words: input.sharedGeneratorTableWords
        )
        let varyingTableBuffer = try ensureBuffer(
            varyingKeyTableBuffer,
            minimumByteCount: tableByteCount
        )
        varyingKeyTableBuffer = varyingTableBuffer
        copy(input.signatureXWords, byteCount: inputByteCount, to: inputBuffer)
        copy(input.packedDigits, byteCount: digitByteCount, to: digitBuffer)
        copy(
            input.varyingVerificationKeyTableWords,
            byteCount: tableByteCount,
            to: varyingTableBuffer
        )
        // SAFETY: Runtime initialization allocates this actor-owned shared
        // buffer with exactly one UInt32 of aligned storage.
        countBuffer.contents().assumingMemoryBound(to: UInt32.self).pointee
            = UInt32(input.recordCount)

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw MetalSchnorrBatchVerificationError.commandEncodingFailed
        }
        encoder.setComputePipelineState(pipeline)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.setBuffer(sharedTableBuffer, offset: 0, index: 3)
        encoder.setBuffer(varyingTableBuffer, offset: 0, index: 4)
        encoder.setBuffer(digitBuffer, offset: 0, index: 5)
        encoder.dispatchThreads(
            MTLSize(width: input.recordCount, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(
                width: Self.resolveThreadgroupWidth(pipeline: pipeline),
                height: 1,
                depth: 1
            )
        )
        encoder.endEncoding()
        let clock = ContinuousClock()
        let executionStart = clock.now
        try await commitAndAwait(commandBuffer)
        let gpuExecutionDuration = executionStart.duration(to: clock.now)
        let readbackStart = clock.now
        let results = try readResults(from: outputBuffer, count: input.recordCount)
        return MetalSchnorrBatchVerificationResult(
            results: results,
            gpuExecutionDuration: gpuExecutionDuration,
            readbackDuration: readbackStart.duration(to: clock.now)
        )
    }

}
#else
extension MetalSchnorrBatchVerificationClient {
    func verify(
        cachedKeyInput: MetalSchnorrCachedKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        throw MetalSchnorrBatchVerificationError.unavailable
    }

    func verify(
        varyingKeyInput: MetalSchnorrVaryingKeyBatchInput
    ) async throws -> MetalSchnorrBatchVerificationResult {
        throw MetalSchnorrBatchVerificationError.unavailable
    }
}
#endif
