// MetalVerificationPreparationCancellationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Metal verification-preparation cancellation validation")
struct MetalVerificationPreparationCancellationValidator {
    @Test("Fixed-key parallel preparation stops after cancellation")
    func stopFixedKeyParallelPreparationAfterCancellation() async throws {
        let fixture = try makeFixture()
        let recordCount = 2_048
        let signatures = Array(repeating: fixture.signature, count: recordCount)
        let digests = Array(repeating: fixture.digest, count: recordCount)
        let expectedResults = Array(repeating: true, count: recordCount)
        let tableWords = PerformanceBenchmarkOperations
            .makeMetalSchnorrVerificationTableWords(
                verificationKey: fixture.verificationKey
            )
        let task = Task(priority: .background) {
            try await PerformanceBenchmarkOperations
                .makeMetalSchnorrVerificationBatchInputParallel(
                    signatures: signatures,
                    digests: digests,
                    expectedResults: expectedResults,
                    verificationKey: fixture.verificationKey,
                    tableWords: tableWords
                )
        }
        try await Task.sleep(for: .milliseconds(5))
        task.cancel()

        await expectCancellation(from: task, operation: "fixed-key preparation")
    }

    @Test("Varying-key parallel preparation stops after cancellation")
    func stopVaryingKeyParallelPreparationAfterCancellation() async throws {
        let fixture = try makeFixture()
        let recordCount = 2_048
        let signatures = Array(repeating: fixture.signature, count: recordCount)
        let digests = Array(repeating: fixture.digest, count: recordCount)
        let expectedResults = Array(repeating: true, count: recordCount)
        let verificationKeys = Array(
            repeating: fixture.verificationKey,
            count: recordCount
        )
        let task = Task(priority: .background) {
            try await PerformanceBenchmarkOperations
                .makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
                    signatures: signatures,
                    digests: digests,
                    expectedResults: expectedResults,
                    verificationKeys: verificationKeys
                )
        }
        try await Task.sleep(for: .milliseconds(5))
        task.cancel()

        await expectCancellation(from: task, operation: "varying-key preparation")
    }

    private func makeFixture() throws -> (
        signature: OpalCrypto.Signature.Schnorr,
        digest: OpalCrypto.Signature.Digest,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) {
        let signingKey = try OpalCryptoTestSupport
            .makeTypedPrivateKey(905)
            .makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest(
            "metal-preparation-cancellation"
        )
        return (
            try signingKey.signSchnorr(digest: digest),
            digest,
            signingKey.verificationKey
        )
    }

    private func expectCancellation<Success: Sendable>(
        from task: Task<Success, any Error>,
        operation: String
    ) async {
        do {
            _ = try await task.value
            Issue.record("Expected cancellation from \(operation).")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected error from \(operation): \(error)")
        }
    }
}
