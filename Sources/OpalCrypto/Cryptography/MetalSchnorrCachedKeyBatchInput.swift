// MetalSchnorrCachedKeyBatchInput.swift

import Foundation

struct MetalSchnorrCachedKeyBatchInput: Sendable {
    let recordCount: Int
    let signatureXWords: [UInt32]
    let packedDigits: [Int8]
    let tableIdentifier: Data
    let tableWords: [UInt32]

    init(
        recordCount: Int,
        signatureXWords: [UInt32],
        packedDigits: [Int8],
        tableIdentifier: Data,
        tableWords: [UInt32]
    ) throws {
        guard recordCount >= 0,
              recordCount <= MetalSchnorrBatchInputPreparationOperation.maximumRecordCount,
              signatureXWords.count == recordCount * 8,
              packedDigits.count
                == recordCount * MetalSchnorrBatchInputPreparationOperation.packedPlaneCount,
              tableWords.count == MetalSchnorrBatchInputPreparationOperation.cachedTableWordCount
        else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
        self.recordCount = recordCount
        self.signatureXWords = signatureXWords
        self.packedDigits = packedDigits
        self.tableIdentifier = Data(tableIdentifier)
        self.tableWords = tableWords
    }
}
