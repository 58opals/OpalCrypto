// DiagnosticsIntegrationValidator~SchnorrBatch.swift

import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Schnorr batch diagnostics record aggregate public-safe fields")
    func validateSchnorrBatchDiagnosticsRecordAggregatePublicSafeFields() throws {
        try withDiagnosticsCapture {
            let fields: [OpalDiagnostics.Field] = [
                .operationField("schnorr_batch_verify"),
                .algorithmField("schnorr"),
                .formatField("bitcoin_cash"),
                .makeSchnorrBatchRequestedPolicyField("automatic"),
                .makeSchnorrBatchSelectedBackendField("metal"),
                .makeSchnorrBatchInputShapeField("varying_keys"),
                .makeSchnorrBatchRecordCountField(4_096),
                .makeSchnorrBatchChunkCountField(10),
                .makeSchnorrBatchValidResultCountField(4_000),
                .makeSchnorrBatchInvalidResultCountField(96),
                .makeSchnorrBatchTotalDurationField(.milliseconds(154)),
                .makeSchnorrBatchPreparationDurationField(.milliseconds(48)),
                .makeSchnorrBatchExecutionDurationField(.milliseconds(105)),
                .makeSchnorrBatchReadbackDurationField(.milliseconds(1))
            ]
            OpalDiagnostics.logger(category: .signature).record(
                event: .schnorrBatchVerifySucceeded,
                level: .opalCryptoDefault(for: .schnorrBatchVerifySucceeded),
                fields: fields
            )

            let record = try #require(
                diagnosticRecord(named: .schnorrBatchVerifySucceeded)
            )
            #expect(record.category == .signature)
            #expect(record.level == .debug)
            expectPublicField("operation", in: record, equals: "schnorr_batch_verify")
            expectPublicField("algorithm", in: record, equals: "schnorr")
            expectPublicField("format", in: record, equals: "bitcoin_cash")
            expectPublicField("requested_policy", in: record, equals: "automatic")
            expectPublicField("selected_backend", in: record, equals: "metal")
            expectPublicField("input_shape", in: record, equals: "varying_keys")
            expectPublicField("record_count", in: record, equals: "4096")
            expectPublicField("chunk_count", in: record, equals: "10")
            expectPublicField("valid_result_count", in: record, equals: "4000")
            expectPublicField("invalid_result_count", in: record, equals: "96")
            #expect(field("total_duration", in: record)?.privacy == .public)
            #expect(field("cpu_preparation_duration", in: record)?.privacy == .public)
            #expect(field("gpu_execution_duration", in: record)?.privacy == .public)
            #expect(field("readback_duration", in: record)?.privacy == .public)

            let forbiddenFieldNames = [
                "signature",
                "digest",
                "public_key",
                "device_name",
                "error_message",
                "result_index"
            ]
            #expect(forbiddenFieldNames.allSatisfy { field($0, in: record) == nil })
        }
    }

    @Test("Schnorr batch fallback diagnostics use stable aggregate reasons")
    func validateSchnorrBatchFallbackDiagnosticsUseStableAggregateReasons() throws {
        try withDiagnosticsCapture {
            OpalDiagnostics.logger(category: .signature).record(
                event: .schnorrBatchVerifyFallback,
                level: .opalCryptoDefault(for: .schnorrBatchVerifyFallback),
                fields: [
                    .operationField("schnorr_batch_verify"),
                    .algorithmField("schnorr"),
                    .formatField("bitcoin_cash"),
                    .makeSchnorrBatchRequestedPolicyField("automatic"),
                    .makeSchnorrBatchSelectedBackendField("cpu"),
                    .makeSchnorrBatchInputShapeField("cached_key"),
                    .makeSchnorrBatchRecordCountField(8_192),
                    .makeSchnorrBatchFallbackReasonField(.metalUnavailable)
                ]
            )

            let record = try #require(diagnosticRecord(named: .schnorrBatchVerifyFallback))
            #expect(record.category == .signature)
            #expect(record.level == .notice)
            expectPublicField("requested_policy", in: record, equals: "automatic")
            expectPublicField("selected_backend", in: record, equals: "cpu")
            expectPublicField("input_shape", in: record, equals: "cached_key")
            expectPublicField("record_count", in: record, equals: "8192")
            expectPublicField("fallback_reason", in: record, equals: "metal_unavailable")
            #expect(field("error_message", in: record) == nil)
            #expect(field("signature", in: record) == nil)
            #expect(field("digest", in: record) == nil)
            #expect(field("public_key", in: record) == nil)
        }
    }

    @Test("Metal Schnorr batch failures map to stable public-safe codes")
    func validateMetalSchnorrBatchFailuresMapToStablePublicSafeCodes() {
        let mappings: [(MetalSchnorrBatchVerificationError, String)] = [
            (.unavailable, "metal_unavailable"),
            (.uncertifiedDevice, "metal_unavailable"),
            (.shaderLibraryUnavailable, "metal_resource_missing"),
            (.pipelineCreationFailed, "metal_pipeline_initialization_failed"),
            (.selfTestFailed, "metal_pipeline_initialization_failed"),
            (.bufferAllocationFailed, "metal_allocation_failed"),
            (.temporaryBufferLimitExceeded, "metal_allocation_failed"),
            (.commandEncodingFailed, "metal_command_failed"),
            (.commandFailed, "metal_command_failed"),
            (.invalidInput, "metal_invalid_output"),
            (.invalidOutput, "metal_invalid_output")
        ]

        for (error, expectedCode) in mappings {
            let fields = OpalDiagnostics.Field.errorFields(error)
            let codeField = fields.first { $0.name == "error_code" }
            let messageField = fields.first { $0.name == "error_message" }

            #expect(codeField?.value == expectedCode)
            #expect(codeField?.privacy == .public)
            #expect(messageField?.redactedValue == "<redacted>")
            #expect(messageField?.privacy == .private)
        }
    }
}
