// MetalSchnorrBatchVerificationResult.swift

struct MetalSchnorrBatchVerificationResult: Sendable {
    static let empty = Self(
        results: [],
        gpuExecutionDuration: .zero,
        readbackDuration: .zero
    )

    let results: [Bool]
    let gpuExecutionDuration: Duration
    let readbackDuration: Duration
}
