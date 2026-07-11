// MetalSchnorrBatchInputPreparationOperation.swift

import Foundation

enum MetalSchnorrBatchInputPreparationOperation {
    static let maximumRecordCount = 8_192
    static let packedComponentCount = 4
    static let packedDigitCount = 130
    static let packedPlaneCount = packedComponentCount * packedDigitCount
    static let cachedOddMultipleCount = 32
    static let varyingKeyOddMultipleCount = 2
    static let cachedTableWordCount = 4 * cachedOddMultipleCount * 16
    static let sharedGeneratorTableWordCount = 2 * cachedOddMultipleCount * 16
    static let varyingKeyTableSlotCount = 2 * varyingKeyOddMultipleCount * 16
    static let sharedGeneratorTableWords = makeSharedGeneratorTableWords()

    private static let minimumRecordsPerTask = 128

    static func makeCachedKeyContext(
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) -> MetalSchnorrCachedKeyContext {
        MetalSchnorrCachedKeyContext(
            verificationKeyModel: verificationKey.verificationKeyModel,
            tableIdentifier: verificationKey.rawRepresentation,
            tableWords: makeCachedKeyTableWords(
                verificationKeyModel: verificationKey.verificationKeyModel
            )
        )
    }

    static func taskRanges(recordCount: Int) -> [Range<Int>] {
        guard recordCount > 0 else { return [] }
        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let taskCount = min(
            processorCount,
            max(1, recordCount / minimumRecordsPerTask)
        )
        let baseCount = recordCount / taskCount
        let remainder = recordCount % taskCount
        return (0..<taskCount).map { taskIndex in
            let lowerBound = taskIndex * baseCount + min(taskIndex, remainder)
            let upperBound = lowerBound
                + baseCount
                + (taskIndex < remainder ? 1 : 0)
            return lowerBound..<upperBound
        }
    }

    static func validateRange(
        _ range: Range<Int>,
        signatureCount: Int,
        digestCount: Int,
        publicKeyCount: Int? = nil
    ) throws {
        guard signatureCount == digestCount,
              publicKeyCount.map({ $0 == signatureCount }) ?? true,
              range.lowerBound >= 0,
              range.upperBound <= signatureCount,
              range.count <= maximumRecordCount
        else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
    }
}
