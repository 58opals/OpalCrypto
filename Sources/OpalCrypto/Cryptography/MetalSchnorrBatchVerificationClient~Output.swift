// MetalSchnorrBatchVerificationClient~Output.swift

extension MetalSchnorrBatchVerificationClient {
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
