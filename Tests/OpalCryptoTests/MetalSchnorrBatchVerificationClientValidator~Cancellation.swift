// MetalSchnorrBatchVerificationClientValidator~Cancellation.swift

import Foundation
import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test(
        "Cancellation discards Metal output and releases the client",
        .enabled(if: MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable)
    )
    func discardMetalOutputAndReleaseClientAfterCancellation() async throws {
        let signingKey = try OpalCryptoTestSupport
            .makeTypedPrivateKey(471)
            .makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest(
            "metal-command-cancellation"
        )
        let signature = try signingKey.signSchnorr(digest: digest)
        let recordCount = 8_192
        let signatures = Array(repeating: signature, count: recordCount)
        let digests = Array(repeating: digest, count: recordCount)
        let context = MetalSchnorrBatchInputPreparationOperation
            .makeCachedKeyContext(verificationKey: signingKey.verificationKey)
        let input = try await MetalSchnorrBatchInputPreparationOperation
            .prepareCachedKeyInput(
                signatures: signatures,
                digests: digests,
                range: signatures.indices,
                context: context
            )
        let task = Task {
            try await MetalSchnorrBatchVerificationClient.shared.verify(
                cachedKeyInput: input
            )
        }
        try await Task.sleep(for: .milliseconds(1))
        task.cancel()

        do {
            _ = try await task.value
            Issue.record("Expected Metal execution cancellation.")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let recoveryInput = try await MetalSchnorrBatchInputPreparationOperation
            .prepareCachedKeyInput(
                signatures: [signature],
                digests: [digest],
                range: 0..<1,
                context: context
            )
        let recoveryResult = try await MetalSchnorrBatchVerificationClient.shared
            .verify(cachedKeyInput: recoveryInput)
        #expect(recoveryResult.results == [true])
    }
}
