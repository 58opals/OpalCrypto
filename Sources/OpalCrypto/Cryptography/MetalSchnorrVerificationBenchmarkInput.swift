// MetalSchnorrVerificationBenchmarkInput.swift

package struct MetalSchnorrVerificationBenchmarkInput: Sendable {
    package let signatureXWords: [UInt32]
    package let windowedNonAdjacentFormDigits: [Int8]
    package let windowedNonAdjacentFormTableWords: [UInt32]
    package let expected: Bool

    package init(
        signatureXWords: [UInt32],
        windowedNonAdjacentFormDigits: [Int8],
        windowedNonAdjacentFormTableWords: [UInt32],
        expected: Bool
    ) {
        self.signatureXWords = signatureXWords
        self.windowedNonAdjacentFormDigits = windowedNonAdjacentFormDigits
        self.windowedNonAdjacentFormTableWords = windowedNonAdjacentFormTableWords
        self.expected = expected
    }
}
