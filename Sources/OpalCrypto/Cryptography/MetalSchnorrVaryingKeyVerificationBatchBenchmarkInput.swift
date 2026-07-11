// MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput.swift

import Foundation

package struct MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput: Sendable {
    package let recordCount: Int
    package let signatureXWords: [UInt32]
    package let windowedNonAdjacentFormDigits: [Int8]
    package let sharedGeneratorTableWords: [UInt32]
    package let varyingVerificationKeyTableWords: [UInt32]
    package let expectedResults: [UInt32]
    package let tableCacheIdentifier: UUID

    init(
        recordCount: Int,
        signatureXWords: [UInt32],
        windowedNonAdjacentFormDigits: [Int8],
        sharedGeneratorTableWords: [UInt32],
        varyingVerificationKeyTableWords: [UInt32],
        expectedResults: [UInt32]
    ) {
        self.recordCount = recordCount
        self.signatureXWords = signatureXWords
        self.windowedNonAdjacentFormDigits = windowedNonAdjacentFormDigits
        self.sharedGeneratorTableWords = sharedGeneratorTableWords
        self.varyingVerificationKeyTableWords = varyingVerificationKeyTableWords
        self.expectedResults = expectedResults
        self.tableCacheIdentifier = UUID()
    }

    package static let cachedSharedGeneratorTableWords = PerformanceBenchmarkOperations
        .makeMetalSchnorrSharedGeneratorTableWords()
}
