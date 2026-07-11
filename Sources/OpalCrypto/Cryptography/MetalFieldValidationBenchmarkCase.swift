// MetalFieldValidationBenchmarkCase.swift

package struct MetalFieldValidationBenchmarkCase: Sendable {
    package let leftWords: [UInt32]
    package let rightWords: [UInt32]
    package let expectedProductWords: [UInt32]
    package let expectedSquareWords: [UInt32]
    package let expectedQuadraticResidue: UInt32

    package init(
        leftWords: [UInt32],
        rightWords: [UInt32],
        expectedProductWords: [UInt32],
        expectedSquareWords: [UInt32],
        expectedQuadraticResidue: UInt32
    ) {
        self.leftWords = leftWords
        self.rightWords = rightWords
        self.expectedProductWords = expectedProductWords
        self.expectedSquareWords = expectedSquareWords
        self.expectedQuadraticResidue = expectedQuadraticResidue
    }
}
