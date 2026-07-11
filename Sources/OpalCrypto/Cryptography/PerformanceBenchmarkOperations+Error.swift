// PerformanceBenchmarkOperations+Error.swift

package extension PerformanceBenchmarkOperations {
    enum Error: Swift.Error, Equatable {
        case mismatchedSchnorrBatchInputCounts(
            signatureCount: Int,
            digestCount: Int,
            verificationKeyCount: Int?
        )
    }
}
