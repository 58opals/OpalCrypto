// BatchDerivationCancellationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Batch-derivation cancellation validation")
struct BatchDerivationCancellationValidator {
    @Test("Pre-cancelled public batch operations throw cancellation")
    func preCancelledPublicBatchOperationsThrowCancellation() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(901)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

        let publicKeyTask = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await OpalCrypto.Secp256k1.derivePublicKeys(
                from: [privateKey]
            )
        }
        await expectCancellation(
            from: publicKeyTask,
            operation: "public-key batch derivation"
        )

        let sharedSecretTask = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await OpalCrypto.Secp256k1.deriveSharedSecrets(
                privateKey: privateKey,
                publicKeys: [publicKey]
            )
        }
        await expectCancellation(
            from: sharedSecretTask,
            operation: "shared-secret batch derivation"
        )
    }

    @Test("Serial and parallel public-key batch derivation stop after cancellation")
    func stopSerialAndParallelPublicKeyBatchDerivationAfterCancellation() async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(902)
        let privateKeys = Array(repeating: privateKey, count: 8_192)
        let executionModes: [StandardsForEfficientCryptography256k1CurveModel.Operation
            .CompressedPublicKeyBatchDerivationExecutionMode] = [.serial, .parallel]

        for executionMode in executionModes {
            let task = Task(priority: .background) {
                try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveCompressedPublicKeys(
                        fromPrivateKeys32: privateKeys,
                        executionMode: executionMode
                    )
            }
            try await Task.sleep(for: .milliseconds(5))
            task.cancel()
            await expectCancellation(
                from: task,
                operation: "\(executionMode) public-key batch derivation"
            )
        }
    }

    @Test("Serial and parallel shared-secret batch derivation stop after cancellation")
    func stopSerialAndParallelSharedSecretBatchDerivationAfterCancellation() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(903)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: OpalCryptoTestSupport.makeTypedPrivateKey(904)
        )
        let publicKeys = Array(repeating: publicKey, count: 2_048)
        let executionModes: [StandardsForEfficientCryptography256k1CurveModel.Operation
            .SharedSecretBatchDerivationExecutionMode] = [.serial, .parallel]

        for executionMode in executionModes {
            let task = Task(priority: .background) {
                try await StandardsForEfficientCryptography256k1CurveModel.Operation
                    .deriveSharedSecrets(
                        privateKey: privateKey,
                        publicKeys: publicKeys,
                        executionMode: executionMode
                    )
            }
            try await Task.sleep(for: .milliseconds(5))
            task.cancel()
            await expectCancellation(
                from: task,
                operation: "\(executionMode) shared-secret batch derivation"
            )
        }
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
