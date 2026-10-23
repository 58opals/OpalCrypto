// SchnorrBatchVerificationExecutionValidator~CancellationAndChunking.swift

import Testing
@testable import OpalCrypto

extension SchnorrBatchVerificationExecutionValidator {
    @Test("Metal cancellation passes through without CPU fallback")
    func propagateMetalCancellationWithoutCPUFallback() async throws {
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: 6)
        let recorder = SchnorrBatchVerificationExecutionCallRecorder()
        let backendClient = SchnorrBatchVerificationExecutionFixture
            .makeMetalSelectedBackendClient(
                recorder: recorder,
                cpuResults: fixture.expectedResults
            ) { _, _ in
                throw CancellationError()
            }

        do {
            _ = try await SchnorrBatchVerificationOperation.verify(
                input: fixture.input,
                policy: .automatic,
                backendClient: backendClient
            )
            Issue.record("Expected Metal cancellation to pass through.")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        #expect(await recorder.metalRecordCounts == [6])
        #expect(await recorder.cpuRecordCounts.isEmpty)
    }
}
