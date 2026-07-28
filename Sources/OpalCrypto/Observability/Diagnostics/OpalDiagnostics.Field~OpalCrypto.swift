// OpalDiagnostics.Field~OpalCrypto.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func publicField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, publicValue: value)
    }

    static func publicField(_ name: String, _ value: Int) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value, privacy: .public)
    }

    static func publicField(_ name: String, _ value: Bool) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value, privacy: .public)
    }

    static func privateField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value, privacy: .private)
    }

    static func operationField(_ operation: String) -> OpalDiagnostics.Field {
        publicField("operation", operation)
    }

    static func algorithmField(_ algorithm: String) -> OpalDiagnostics.Field {
        publicField("algorithm", algorithm)
    }

    static func formatField(_ format: String) -> OpalDiagnostics.Field {
        publicField("format", format)
    }

    static func inputLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("input_byte_count", count)
    }

    static func outputLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("output_byte_count", count)
    }

    static func messageLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("message_byte_count", count)
    }

    static func signatureLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("signature_byte_count", count)
    }

    static func ciphertextLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("ciphertext_byte_count", count)
    }

    static func resultField(_ result: Bool) -> OpalDiagnostics.Field {
        publicField("verification_result", result)
    }

    static func makeSchnorrBatchRequestedPolicyField(
        _ requestedPolicy: String
    ) -> OpalDiagnostics.Field {
        publicField("requested_policy", requestedPolicy)
    }

    static func makeSchnorrBatchSelectedBackendField(
        _ selectedBackend: String
    ) -> OpalDiagnostics.Field {
        publicField("selected_backend", selectedBackend)
    }

    static func makeSchnorrBatchInputShapeField(
        _ inputShape: String
    ) -> OpalDiagnostics.Field {
        publicField("input_shape", inputShape)
    }

    static func makeSchnorrBatchRecordCountField(_ recordCount: Int) -> OpalDiagnostics.Field {
        publicField("record_count", recordCount)
    }

    static func makeSchnorrBatchChunkCountField(_ chunkCount: Int) -> OpalDiagnostics.Field {
        publicField("chunk_count", chunkCount)
    }

    static func makeSchnorrBatchValidResultCountField(
        _ validResultCount: Int
    ) -> OpalDiagnostics.Field {
        publicField("valid_result_count", validResultCount)
    }

    static func makeSchnorrBatchInvalidResultCountField(
        _ invalidResultCount: Int
    ) -> OpalDiagnostics.Field {
        publicField("invalid_result_count", invalidResultCount)
    }

    static func makeSchnorrBatchTotalDurationField(
        _ totalDuration: Duration
    ) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(
            name: "total_duration",
            value: totalDuration,
            privacy: .public
        )
    }

    static func makeSchnorrBatchPreparationDurationField(
        _ preparationDuration: Duration
    ) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(
            name: "cpu_preparation_duration",
            value: preparationDuration,
            privacy: .public
        )
    }

    static func makeSchnorrBatchExecutionDurationField(
        _ executionDuration: Duration
    ) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(
            name: "gpu_execution_duration",
            value: executionDuration,
            privacy: .public
        )
    }

    static func makeSchnorrBatchReadbackDurationField(
        _ readbackDuration: Duration
    ) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(
            name: "readback_duration",
            value: readbackDuration,
            privacy: .public
        )
    }

    static func makeSchnorrBatchFallbackReasonField(
        _ fallbackReason: OpalDiagnostics.ErrorCode
    ) -> OpalDiagnostics.Field {
        publicField("fallback_reason", fallbackReason.rawValue)
    }

    static func errorFields(_ error: Swift.Error) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.errorCode(errorCode(for: error)),
            OpalDiagnostics.Field.errorType(error),
            OpalDiagnostics.Field.errorMessage(String(describing: error))
        ]
    }
}
