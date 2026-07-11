// SchnorrBatchVerificationBackendClient.swift

struct SchnorrBatchVerificationBackendClient: Sendable {
    typealias BackendSelection = @Sendable (
        _ recordCount: Int,
        _ policy: OpalCrypto.BatchExecutionPolicy
    ) async -> SchnorrBatchVerificationBackend

    typealias BackendExecution = @Sendable (
        _ input: SchnorrBatchVerificationInput,
        _ initialCPUPreparationDuration: Duration?
    ) async throws -> SchnorrBatchVerificationExecutionResult

    private let backendSelection: BackendSelection
    private let cpuExecution: BackendExecution
    private let metalExecution: BackendExecution

    init(
        backendSelection: @escaping BackendSelection,
        cpuExecution: @escaping BackendExecution,
        metalExecution: @escaping BackendExecution
    ) {
        self.backendSelection = backendSelection
        self.cpuExecution = cpuExecution
        self.metalExecution = metalExecution
    }

    func selectBackend(
        recordCount: Int,
        policy: OpalCrypto.BatchExecutionPolicy
    ) async -> SchnorrBatchVerificationBackend {
        await backendSelection(recordCount, policy)
    }

    func executeUsingCPU(
        input: SchnorrBatchVerificationInput,
        initialCPUPreparationDuration: Duration?
    ) async throws -> SchnorrBatchVerificationExecutionResult {
        try await cpuExecution(input, initialCPUPreparationDuration)
    }

    func executeUsingMetal(
        input: SchnorrBatchVerificationInput,
        initialCPUPreparationDuration: Duration?
    ) async throws -> SchnorrBatchVerificationExecutionResult {
        try await metalExecution(input, initialCPUPreparationDuration)
    }
}

extension SchnorrBatchVerificationBackendClient {
    static let live = Self(
        backendSelection: { recordCount, policy in
            await SchnorrBatchVerificationOperation.selectBackend(
                recordCount: recordCount,
                policy: policy
            )
        },
        cpuExecution: { input, initialCPUPreparationDuration in
            try await SchnorrBatchVerificationOperation.executeUsingCPU(
                input: input,
                initialCPUPreparationDuration: initialCPUPreparationDuration
            )
        },
        metalExecution: { input, initialCPUPreparationDuration in
            try await SchnorrBatchVerificationOperation.executeUsingMetal(
                input: input,
                initialCPUPreparationDuration: initialCPUPreparationDuration
            )
        }
    )
}
