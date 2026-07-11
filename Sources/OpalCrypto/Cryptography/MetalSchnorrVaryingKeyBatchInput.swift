// MetalSchnorrVaryingKeyBatchInput.swift

struct MetalSchnorrVaryingKeyBatchInput: Sendable {
    let recordCount: Int
    let signatureXWords: [UInt32]
    let packedDigits: [Int8]
    let sharedGeneratorTableWords: [UInt32]
    let varyingVerificationKeyTableWords: [UInt32]

    init(
        recordCount: Int,
        signatureXWords: [UInt32],
        packedDigits: [Int8],
        sharedGeneratorTableWords: [UInt32],
        varyingVerificationKeyTableWords: [UInt32]
    ) throws {
        guard recordCount >= 0,
              recordCount <= MetalSchnorrBatchInputPreparationOperation.maximumRecordCount,
              signatureXWords.count == recordCount * 8,
              packedDigits.count
                == recordCount * MetalSchnorrBatchInputPreparationOperation.packedPlaneCount,
              sharedGeneratorTableWords.count
                == MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWordCount,
              varyingVerificationKeyTableWords.count
                == recordCount
                    * MetalSchnorrBatchInputPreparationOperation.varyingKeyTableSlotCount
        else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
        self.recordCount = recordCount
        self.signatureXWords = signatureXWords
        self.packedDigits = packedDigits
        self.sharedGeneratorTableWords = sharedGeneratorTableWords
        self.varyingVerificationKeyTableWords = varyingVerificationKeyTableWords
    }
}
