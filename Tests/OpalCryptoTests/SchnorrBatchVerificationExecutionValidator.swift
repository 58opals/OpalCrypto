// SchnorrBatchVerificationExecutionValidator.swift

import Testing
@testable import OpalCrypto

@Suite("Schnorr batch verification execution")
struct SchnorrBatchVerificationExecutionValidator {
    @Test("Automatic execution discards partial Metal results and retries the whole batch")
    func recomputeEntireBatchUsingCPUAfterAutomaticMetalFailure() async throws {
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: 6)
        let recorder = SchnorrBatchVerificationExecutionCallRecorder()
        let simulatedPartialResults = [false, false]
        let backendClient = SchnorrBatchVerificationExecutionFixture
            .makeMetalSelectedBackendClient(
                recorder: recorder,
                cpuResults: fixture.expectedResults
            ) { _, _ in
                await recorder.recordPartialMetalResults(
                    resultCount: simulatedPartialResults.count
                )
                throw MetalSchnorrBatchVerificationError.commandFailed
            }

        let results = try await SchnorrBatchVerificationOperation.verify(
            input: fixture.input,
            policy: .automatic,
            backendClient: backendClient
        )

        #expect(results == fixture.expectedResults)
        #expect(Array(results.prefix(2)) != simulatedPartialResults)
        #expect(await recorder.metalRecordCounts == [6])
        #expect(await recorder.partialMetalResultCounts == [2])
        #expect(await recorder.cpuRecordCounts == [6])
    }

    @Test("Forced Metal execution maps failure without CPU fallback")
    func avoidCPUFallbackAfterForcedMetalFailure() async throws {
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: 6)
        let recorder = SchnorrBatchVerificationExecutionCallRecorder()
        let backendClient = SchnorrBatchVerificationExecutionFixture
            .makeMetalSelectedBackendClient(
                recorder: recorder,
                cpuResults: fixture.expectedResults
            ) { _, _ in
                throw MetalSchnorrBatchVerificationError.commandFailed
            }

        do {
            _ = try await SchnorrBatchVerificationOperation.verify(
                input: fixture.input,
                policy: .metal,
                backendClient: backendClient
            )
            Issue.record("Expected forced Metal execution to fail.")
        } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            #expect(error == .executionFailed(policy: .metal))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        #expect(await recorder.metalRecordCounts == [6])
        #expect(await recorder.cpuRecordCounts.isEmpty)
    }
}
