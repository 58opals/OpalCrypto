// MetalSchnorrBatchVerificationClientValidator~Allocation.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test("Temporary buffer sizing rounds to bounded powers of two")
    func roundTemporaryBufferSizesWithinBudget() throws {
        let client = MetalSchnorrBatchVerificationClient.self
        #expect(
            try client.replacementBufferByteCount(
                minimumByteCount: 1,
                allocatedBufferByteCount: 0
            ) == 256
        )
        #expect(
            try client.replacementBufferByteCount(
                minimumByteCount: 257,
                allocatedBufferByteCount: 0
            ) == 512
        )
        #expect(
            try client.replacementBufferByteCount(
                minimumByteCount: client.maximumTemporaryBufferByteCount,
                allocatedBufferByteCount: 0
            ) == client.maximumTemporaryBufferByteCount
        )
    }

    @Test("Temporary buffer sizing accounts for every live allocation")
    func accountForEveryLiveAllocationWithinTemporaryBufferBudget() throws {
        let client = MetalSchnorrBatchVerificationClient.self
        let maximumByteCount = client.maximumTemporaryBufferByteCount

        #expect(
            try client.replacementBufferByteCount(
                minimumByteCount: 1,
                allocatedBufferByteCount: maximumByteCount - 256
            ) == 256
        )
        #expect(
            throws: MetalSchnorrBatchVerificationError
                .temporaryBufferLimitExceeded
        ) {
            try client.replacementBufferByteCount(
                minimumByteCount: 1,
                allocatedBufferByteCount: maximumByteCount - 255
            )
        }
    }

    @Test("Temporary buffer sizing rejects over-budget and invalid arithmetic")
    func rejectInvalidTemporaryBufferBudgetArithmetic() {
        let client = MetalSchnorrBatchVerificationClient.self
        let maximumByteCount = client.maximumTemporaryBufferByteCount

        #expect(
            throws: MetalSchnorrBatchVerificationError
                .temporaryBufferLimitExceeded
        ) {
            try client.replacementBufferByteCount(
                minimumByteCount: Int.max,
                allocatedBufferByteCount: 0
            )
        }
        #expect(throws: MetalSchnorrBatchVerificationError.invalidInput) {
            try client.replacementBufferByteCount(
                minimumByteCount: 256,
                allocatedBufferByteCount: maximumByteCount + 1
            )
        }
    }
}
