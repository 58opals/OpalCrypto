// SchnorrBatchVerificationExecutionResult.swift

struct SchnorrBatchVerificationExecutionResult: Sendable {
    let results: [Bool]
    let backend: SchnorrBatchVerificationBackend
    let chunkCount: Int
    let cpuPreparationDuration: Duration?
    let gpuExecutionDuration: Duration?
    let readbackDuration: Duration?
}
