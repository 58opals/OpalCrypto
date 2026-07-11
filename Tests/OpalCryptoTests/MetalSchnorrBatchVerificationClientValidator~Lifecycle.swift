// MetalSchnorrBatchVerificationClientValidator~Lifecycle.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test("Cancellation removes a queued in-flight operation")
    func removeQueuedInFlightOperationWhenCancelled() async throws {
        let client = MetalSchnorrBatchVerificationClient()
        try await client.acquireExecution()
        let queuedOperation = Task {
            try await client.acquireExecution()
            await client.releaseExecution()
        }

        var observedQueuedOperation = false
        for _ in 0..<10_000 {
            if await client.executionWaiterCount == 1 {
                observedQueuedOperation = true
                break
            }
            await Task.yield()
        }
        #expect(observedQueuedOperation)

        queuedOperation.cancel()
        do {
            try await queuedOperation.value
            Issue.record("Expected queued operation cancellation.")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected queued operation error: \(error)")
        }
        #expect(await client.executionWaiterCount == 0)

        await client.releaseExecution()
        try await client.acquireExecution()
        await client.releaseExecution()
    }

    @Test("Cancelled waiters do not leave stale queue state")
    func discardStaleQueueStateAfterCancellingWaiters() async throws {
        let client = MetalSchnorrBatchVerificationClient()
        try await client.acquireExecution()

        var queuedOperations: [Task<Void, Swift.Error>] = .init()
        for expectedWaiterCount in 1...96 {
            queuedOperations.append(
                Task {
                    try await client.acquireExecution()
                    await client.releaseExecution()
                }
            )
            for _ in 0..<10_000 {
                if await client.executionWaiterCount == expectedWaiterCount {
                    break
                }
                await Task.yield()
            }
            #expect(await client.executionWaiterCount == expectedWaiterCount)
        }

        for queuedOperation in queuedOperations {
            queuedOperation.cancel()
        }
        for queuedOperation in queuedOperations {
            do {
                try await queuedOperation.value
                Issue.record("Expected queued operation cancellation.")
            } catch is CancellationError {
                // Expected.
            } catch {
                Issue.record("Unexpected queued operation error: \(error)")
            }
        }
        #expect(await client.executionWaiterCount == 0)

        await client.releaseExecution()
        try await client.acquireExecution()
        await client.releaseExecution()
    }
}
