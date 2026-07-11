// SchnorrBatchVerificationOperation~Execution.swift

import Foundation

extension SchnorrBatchVerificationOperation {
    static let minimumWarmAutomaticMetalRecordCount = 4_096
    static let minimumColdAutomaticMetalRecordCount = 8_192

    static func verify(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        backendClient: SchnorrBatchVerificationBackendClient = .live
    ) async throws -> [Bool] {
        try Task.checkCancellation()
        let clock = ContinuousClock()
        let start = clock.now
        let normalizationStart = clock.now
        let executionInput = normalize(input)
        let normalizationDuration: Duration? = switch input.keyInput {
        case .cached:
            nil
        case .varying where input.recordCount > 0:
            normalizationStart.duration(to: clock.now)
        case .varying:
            nil
        }
        let selectedBackend = await backendClient.selectBackend(
            recordCount: executionInput.recordCount,
            policy: policy
        )
        SchnorrBatchVerificationDiagnostics.recordBegin(
            input: input,
            policy: policy,
            selectedBackend: selectedBackend.rawValue
        )

        do {
            let executionResult = try await execute(
                input: executionInput,
                diagnosticsInput: input,
                policy: policy,
                selectedBackend: selectedBackend,
                initialCPUPreparationDuration: normalizationDuration,
                start: start,
                clock: clock,
                backendClient: backendClient
            )
            SchnorrBatchVerificationDiagnostics.recordSucceeded(
                input: input,
                policy: policy,
                selectedBackend: executionResult.backend.rawValue,
                chunkCount: executionResult.chunkCount,
                results: executionResult.results,
                totalDuration: start.duration(to: clock.now),
                preparationDuration: executionResult.cpuPreparationDuration,
                executionDuration: executionResult.gpuExecutionDuration,
                readbackDuration: executionResult.readbackDuration
            )
            return executionResult.results
        } catch let error as CancellationError {
            throw error
        } catch {
            SchnorrBatchVerificationDiagnostics.recordFailed(
                input: input,
                policy: policy,
                selectedBackend: selectedBackend.rawValue,
                error: error,
                totalDuration: start.duration(to: clock.now)
            )
            throw makePublicError(error, policy: policy)
        }
    }

    static func execute(
        input: SchnorrBatchVerificationInput,
        diagnosticsInput: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        selectedBackend: SchnorrBatchVerificationBackend,
        initialCPUPreparationDuration: Duration?,
        start: ContinuousClock.Instant,
        clock: ContinuousClock,
        backendClient: SchnorrBatchVerificationBackendClient
    ) async throws -> SchnorrBatchVerificationExecutionResult {
        guard input.recordCount > 0 else {
            return emptyExecutionResult
        }
        switch policy.executionMode {
        case .cpu:
            return try await backendClient.executeUsingCPU(
                input: input,
                initialCPUPreparationDuration: initialCPUPreparationDuration
            )
        case .metal:
            return try await backendClient.executeUsingMetal(
                input: input,
                initialCPUPreparationDuration: initialCPUPreparationDuration
            )
        case .automatic:
            guard selectedBackend == .metal else {
                return try await backendClient.executeUsingCPU(
                    input: input,
                    initialCPUPreparationDuration: initialCPUPreparationDuration
                )
            }
            do {
                return try await backendClient.executeUsingMetal(
                    input: input,
                    initialCPUPreparationDuration: initialCPUPreparationDuration
                )
            } catch let error as CancellationError {
                throw error
            } catch {
                SchnorrBatchVerificationDiagnostics.recordFallback(
                    input: diagnosticsInput,
                    policy: policy,
                    error: error,
                    totalDuration: start.duration(to: clock.now)
                )
                try Task.checkCancellation()
                return try await backendClient.executeUsingCPU(
                    input: input,
                    initialCPUPreparationDuration: initialCPUPreparationDuration
                )
            }
        }
    }

    static func executeUsingCPU(
        input: SchnorrBatchVerificationInput,
        initialCPUPreparationDuration: Duration?
    ) async throws -> SchnorrBatchVerificationExecutionResult {
        SchnorrBatchVerificationExecutionResult(
            results: try await verifyUsingCPU(input: input),
            backend: .cpu,
            chunkCount: cpuTaskCount(recordCount: input.recordCount),
            cpuPreparationDuration: initialCPUPreparationDuration,
            gpuExecutionDuration: nil,
            readbackDuration: nil
        )
    }

}
