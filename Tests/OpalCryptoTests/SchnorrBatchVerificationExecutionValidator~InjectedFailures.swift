// SchnorrBatchVerificationExecutionValidator~InjectedFailures.swift

import Testing
@testable import OpalCrypto

extension SchnorrBatchVerificationExecutionValidator {
    @Test("Automatic execution recovers from every injected Metal failure class")
    func recoverFromInjectedMetalFailureClasses() async throws {
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: 6)

        for injectedError in injectedMetalFailureClasses {
            let recorder = SchnorrBatchVerificationExecutionCallRecorder()
            let backendClient = SchnorrBatchVerificationExecutionFixture
                .makeMetalSelectedBackendClient(
                    recorder: recorder,
                    cpuResults: fixture.expectedResults
                ) { _, _ in
                    throw injectedError
                }

            let results = try await SchnorrBatchVerificationOperation.verify(
                input: fixture.input,
                policy: .automatic,
                backendClient: backendClient
            )

            #expect(results == fixture.expectedResults)
            #expect(await recorder.metalRecordCounts == [6])
            #expect(await recorder.cpuRecordCounts == [6])
        }
    }

    @Test("Forced Metal maps every injected failure class without fallback")
    func mapInjectedForcedMetalFailureClassesWithoutFallback() async throws {
        let fixture = try SchnorrBatchVerificationExecutionFixture
            .makeInput(recordCount: 6)

        for injectedError in injectedMetalFailureClasses {
            let recorder = SchnorrBatchVerificationExecutionCallRecorder()
            let backendClient = SchnorrBatchVerificationExecutionFixture
                .makeMetalSelectedBackendClient(
                    recorder: recorder,
                    cpuResults: fixture.expectedResults
                ) { _, _ in
                    throw injectedError
                }
            let expectedError: OpalCrypto.Signature.Schnorr.VerificationBatch.Error
                = switch injectedError {
                case .unavailable:
                    .executionUnavailable(policy: .metal)
                default:
                    .executionFailed(policy: .metal)
                }

            do {
                _ = try await SchnorrBatchVerificationOperation.verify(
                    input: fixture.input,
                    policy: .metal,
                    backendClient: backendClient
                )
                Issue.record("Expected forced Metal execution to fail.")
            } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
                #expect(error == expectedError)
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }

            #expect(await recorder.metalRecordCounts == [6])
            #expect(await recorder.cpuRecordCounts.isEmpty)
        }
    }

    private var injectedMetalFailureClasses: [MetalSchnorrBatchVerificationError] {
        [
            .unavailable,
            .shaderLibraryUnavailable,
            .pipelineCreationFailed,
            .bufferAllocationFailed,
            .commandFailed,
            .invalidOutput
        ]
    }
}
