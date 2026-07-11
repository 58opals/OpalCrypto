// MetalSchnorrVerificationBatchBenchmarkInput.swift

package struct MetalSchnorrVerificationBatchBenchmarkInput: Sendable {
    package let recordCount: Int
    package let signatureXWords: [UInt32]
    package let windowedNonAdjacentFormDigits: [Int8]
    package let windowedNonAdjacentFormTableWords: [UInt32]
    package let expectedResults: [UInt32]

    package init(
        recordCount: Int,
        signatureXWords: [UInt32],
        windowedNonAdjacentFormDigits: [Int8],
        windowedNonAdjacentFormTableWords: [UInt32],
        expectedResults: [UInt32]
    ) {
        self.recordCount = recordCount
        self.signatureXWords = signatureXWords
        self.windowedNonAdjacentFormDigits = windowedNonAdjacentFormDigits
        self.windowedNonAdjacentFormTableWords = windowedNonAdjacentFormTableWords
        self.expectedResults = expectedResults
    }

    package var checksum: Int {
        var checksum = recordCount
        for (index, expectedResult) in expectedResults.enumerated() {
            checksum ^= expectedResult == 1 ? index + 1 : -(index + 1)
        }
        checksum ^= signatureXWords.count
        checksum ^= windowedNonAdjacentFormDigits.count
        checksum ^= windowedNonAdjacentFormTableWords.count
        return checksum
    }
}
