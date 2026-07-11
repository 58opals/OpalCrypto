// MetalSchnorrBatchVerificationClient~Output.swift

extension MetalSchnorrBatchVerificationClient {
    // SAFETY: The buffer is borrowed only for this synchronous iteration and
    // every read is bounded by outputWords.count. Production callers retain the
    // actor-owned MTLBuffer for the call, while array-backed test callers retain
    // their array for the withUnsafeBufferPointer closure.
    nonisolated static func decodeOutputWords(
        _ outputWords: UnsafeBufferPointer<UInt32>
    ) throws -> [Bool] {
        var results: [Bool] = []
        results.reserveCapacity(outputWords.count)
        for outputWord in outputWords {
            switch outputWord {
            case 0:
                results.append(false)
            case 1:
                results.append(true)
            default:
                throw MetalSchnorrBatchVerificationError.invalidOutput
            }
        }
        return results
    }
}
