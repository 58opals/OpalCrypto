// MetalSchnorrBatchVerificationClient~Allocation.swift

extension MetalSchnorrBatchVerificationClient {
    nonisolated static func replacementBufferByteCount(
        minimumByteCount: Int,
        allocatedBufferByteCount: Int
    ) throws -> Int {
        guard minimumByteCount > 0,
              allocatedBufferByteCount >= 0,
              allocatedBufferByteCount <= maximumTemporaryBufferByteCount
        else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
        guard minimumByteCount <= maximumTemporaryBufferByteCount else {
            throw MetalSchnorrBatchVerificationError.temporaryBufferLimitExceeded
        }

        var replacementByteCount = 256
        while replacementByteCount < minimumByteCount {
            replacementByteCount *= 2
        }
        guard replacementByteCount
                <= maximumTemporaryBufferByteCount - allocatedBufferByteCount
        else {
            throw MetalSchnorrBatchVerificationError.temporaryBufferLimitExceeded
        }
        return replacementByteCount
    }
}
