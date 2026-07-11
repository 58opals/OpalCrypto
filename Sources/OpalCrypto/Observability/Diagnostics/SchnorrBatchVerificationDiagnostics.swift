// SchnorrBatchVerificationDiagnostics.swift

import OpalDiagnostics

enum SchnorrBatchVerificationDiagnostics {
    static func recordBegin(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        selectedBackend: String
    ) {
        record(
            event: .schnorrBatchVerifyBegin,
            fields: makeBaseFields(
                input: input,
                policy: policy,
                selectedBackend: selectedBackend
            )
        )
    }

    static func recordSucceeded(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        selectedBackend: String,
        chunkCount: Int,
        results: [Bool],
        totalDuration: Duration,
        preparationDuration: Duration? = nil,
        executionDuration: Duration? = nil,
        readbackDuration: Duration? = nil
    ) {
        let validResultCount = results.lazy.filter { $0 }.count
        var fields = makeBaseFields(
            input: input,
            policy: policy,
            selectedBackend: selectedBackend
        )
        fields.append(contentsOf: [
            .makeSchnorrBatchChunkCountField(chunkCount),
            .makeSchnorrBatchValidResultCountField(validResultCount),
            .makeSchnorrBatchInvalidResultCountField(results.count - validResultCount),
            .makeSchnorrBatchTotalDurationField(totalDuration)
        ])
        if let preparationDuration {
            fields.append(.makeSchnorrBatchPreparationDurationField(preparationDuration))
        }
        if let executionDuration {
            fields.append(.makeSchnorrBatchExecutionDurationField(executionDuration))
        }
        if let readbackDuration {
            fields.append(.makeSchnorrBatchReadbackDurationField(readbackDuration))
        }
        record(event: .schnorrBatchVerifySucceeded, fields: fields)
    }

    static func recordFailed(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        selectedBackend: String,
        error: Swift.Error,
        totalDuration: Duration
    ) {
        let fields = makeBaseFields(
            input: input,
            policy: policy,
            selectedBackend: selectedBackend
        ) + [
            .makeSchnorrBatchTotalDurationField(totalDuration)
        ] + OpalDiagnostics.Field.errorFields(error)
        record(event: .schnorrBatchVerifyFailed, fields: fields)
    }

    static func recordFallback(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        error: Swift.Error,
        totalDuration: Duration
    ) {
        let fields = makeBaseFields(
            input: input,
            policy: policy,
            selectedBackend: "cpu"
        ) + [
            .makeSchnorrBatchTotalDurationField(totalDuration),
            .makeSchnorrBatchFallbackReasonField(
                OpalDiagnostics.Field.errorCode(for: error)
            )
        ] + OpalDiagnostics.Field.errorFields(error)
        record(event: .schnorrBatchVerifyFallback, fields: fields)
    }

    static func makePolicyName(
        _ policy: OpalCrypto.BatchExecutionPolicy
    ) -> String {
        switch policy.executionMode {
        case .automatic:
            "automatic"
        case .cpu:
            "cpu"
        case .metal:
            "metal"
        }
    }

    private static func makeBaseFields(
        input: SchnorrBatchVerificationInput,
        policy: OpalCrypto.BatchExecutionPolicy,
        selectedBackend: String
    ) -> [OpalDiagnostics.Field] {
        [
            .operationField("schnorr_batch_verify"),
            .algorithmField("schnorr"),
            .formatField("bitcoin_cash"),
            .makeSchnorrBatchRequestedPolicyField(makePolicyName(policy)),
            .makeSchnorrBatchSelectedBackendField(selectedBackend),
            .makeSchnorrBatchInputShapeField(makeInputShape(input)),
            .makeSchnorrBatchRecordCountField(input.recordCount)
        ]
    }

    private static func makeInputShape(
        _ input: SchnorrBatchVerificationInput
    ) -> String {
        switch input.keyInput {
        case .cached:
            "cached_key"
        case .varying:
            "varying_keys"
        }
    }

    private static func record(
        event: OpalDiagnostics.Event,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: .signature).record(
            event: event,
            level: .opalCryptoDefault(for: event),
            fields: fields
        )
    }
}
