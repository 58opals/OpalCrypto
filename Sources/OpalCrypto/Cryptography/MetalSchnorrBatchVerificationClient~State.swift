// MetalSchnorrBatchVerificationClient~State.swift

extension MetalSchnorrBatchVerificationClient {
    var isRuntimeWarm: Bool {
        hasPassedSelfTest && !isQuarantined
    }
}
