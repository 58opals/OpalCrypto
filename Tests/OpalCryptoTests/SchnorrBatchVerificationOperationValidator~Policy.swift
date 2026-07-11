// SchnorrBatchVerificationOperationValidator~Policy.swift

import Testing
@testable import OpalCrypto

extension SchnorrBatchVerificationOperationValidator {
    @Test("Automatic Metal thresholds preserve cold and warm boundaries")
    func preserveColdAndWarmAutomaticMetalThresholds() {
        #expect(
            !SchnorrBatchVerificationOperation.meetsAutomaticMetalThreshold(
                recordCount: 4_095,
                isRuntimeWarm: true
            )
        )
        #expect(
            SchnorrBatchVerificationOperation.meetsAutomaticMetalThreshold(
                recordCount: 4_096,
                isRuntimeWarm: true
            )
        )
        #expect(
            !SchnorrBatchVerificationOperation.meetsAutomaticMetalThreshold(
                recordCount: 8_191,
                isRuntimeWarm: false
            )
        )
        #expect(
            SchnorrBatchVerificationOperation.meetsAutomaticMetalThreshold(
                recordCount: 8_192,
                isRuntimeWarm: false
            )
        )
    }
}
