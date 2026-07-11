// MetalSchnorrBatchVerificationClient~Command.swift

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal

extension MetalSchnorrBatchVerificationClient {
    func commitAndAwait(_ commandBuffer: any MTLCommandBuffer) async throws {
        let completed = await withCheckedContinuation { continuation in
            commandBuffer.addCompletedHandler { completedBuffer in
                continuation.resume(returning: completedBuffer.status == .completed)
            }
            commandBuffer.commit()
        }
        try Task.checkCancellation()
        guard completed else {
            throw MetalSchnorrBatchVerificationError.commandFailed
        }
    }

    func readResults(
        from outputBuffer: any MTLBuffer,
        count: Int
    ) throws -> [Bool] {
        guard count >= 0,
              count <= outputBuffer.length / MemoryLayout<UInt32>.stride
        else {
            throw MetalSchnorrBatchVerificationError.invalidOutput
        }
        // SAFETY: MTLBuffer storage is suitably aligned, remains owned by the
        // actor for this synchronous read, and the guard bounds every word.
        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: count
        )
        return try Self.decodeOutputWords(
            UnsafeBufferPointer(start: output, count: count)
        )
    }
}
#endif
