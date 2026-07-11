// SchnorrBatchVerificationExecutionFixture.swift

@testable import OpalCrypto

enum SchnorrBatchVerificationExecutionFixture {
    static func makeInput(
        recordCount: Int
    ) throws -> (
        input: SchnorrBatchVerificationInput,
        expectedResults: [Bool]
    ) {
        let signingKey = try OpalCryptoTestSupport
            .makeTypedPrivateKey(431)
            .makeSigningKey()
        let validDigest = try OpalCryptoTestSupport.makeDigest(
            "coordinator-valid-record"
        )
        let invalidDigest = try OpalCryptoTestSupport.makeDigest(
            "coordinator-invalid-record"
        )
        let signature = try signingKey.signSchnorr(digest: validDigest)
        let expectedResults = (0..<recordCount).map {
            !$0.isMultiple(of: 4)
        }
        let digests = expectedResults.map {
            $0 ? validDigest : invalidDigest
        }
        return (
            SchnorrBatchVerificationInput(
                signatures: Array(repeating: signature, count: recordCount),
                digests: digests,
                verificationKey: signingKey.verificationKey
            ),
            expectedResults
        )
    }

    static func makeMetalSelectedBackendClient(
        recorder: SchnorrBatchVerificationExecutionCallRecorder,
        cpuResults: [Bool],
        metalExecution: @escaping SchnorrBatchVerificationBackendClient
            .BackendExecution
    ) -> SchnorrBatchVerificationBackendClient {
        SchnorrBatchVerificationBackendClient(
            backendSelection: { _, _ in .metal },
            cpuExecution: { input, initialCPUPreparationDuration in
                await recorder.recordCPUExecution(
                    recordCount: input.recordCount
                )
                return SchnorrBatchVerificationExecutionResult(
                    results: cpuResults,
                    backend: .cpu,
                    chunkCount: SchnorrBatchVerificationOperation.cpuTaskCount(
                        recordCount: input.recordCount
                    ),
                    cpuPreparationDuration: initialCPUPreparationDuration,
                    gpuExecutionDuration: nil,
                    readbackDuration: nil
                )
            },
            metalExecution: { input, initialCPUPreparationDuration in
                await recorder.recordMetalExecution(
                    recordCount: input.recordCount
                )
                return try await metalExecution(
                    input,
                    initialCPUPreparationDuration
                )
            }
        )
    }
}
