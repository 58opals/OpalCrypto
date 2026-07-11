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

    @Test("Automatic execution retries all 8,193 records after a later Metal chunk fails")
    func recomputeEveryRecordAfterLaterMetalChunkFailure() async throws {
        let recordCount = 8_193
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: recordCount)
        let recorder = SchnorrBatchVerificationExecutionCallRecorder()
        let backendClient = SchnorrBatchVerificationExecutionFixture
            .makeMetalSelectedBackendClient(
                recorder: recorder,
                cpuResults: fixture.expectedResults
            ) { _, _ in
                await recorder.recordPartialMetalResults(resultCount: 8_192)
                throw MetalSchnorrBatchVerificationError.commandFailed
            }

        let results = try await SchnorrBatchVerificationOperation.verify(
            input: fixture.input,
            policy: .automatic,
            backendClient: backendClient
        )

        #expect(results.count == recordCount)
        #expect(results == fixture.expectedResults)
        #expect(await recorder.metalRecordCounts == [recordCount])
        #expect(await recorder.partialMetalResultCounts == [8_192])
        #expect(await recorder.cpuRecordCounts == [recordCount])
    }
}
