// MetalSchnorrBatchVerificationClient~SelfTest.swift

#if canImport(Metal) && canImport(OpalCryptoMetal)
extension MetalSchnorrBatchVerificationClient {
    func performSelfTestIfNeeded() async throws {
        guard !hasPassedSelfTest else { return }
        guard !isQuarantined else {
            throw MetalSchnorrBatchVerificationError.selfTestFailed
        }
        do {
            let inputs = try await MetalSchnorrBatchInputPreparationOperation
                .prepareSelfTestInputs()
            let cachedResults = try await execute(
                cachedKeyInput: inputs.cachedKey
            )
            let varyingResults = try await execute(
                varyingKeyInput: inputs.varyingKey
            )
            guard cachedResults.results == [true, false],
                  varyingResults.results == [true, false]
            else {
                throw MetalSchnorrBatchVerificationError.selfTestFailed
            }
            hasPassedSelfTest = true
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            isQuarantined = true
            throw MetalSchnorrBatchVerificationError.selfTestFailed
        }
    }
}
#endif
