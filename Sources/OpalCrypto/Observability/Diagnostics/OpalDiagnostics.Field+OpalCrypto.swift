// OpalDiagnostics.Field+OpalCrypto.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func publicField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, publicValue: value)
    }

    static func publicField(_ name: String, _ value: Int) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value)
    }

    static func publicField(_ name: String, _ value: Bool) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value)
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

    static func errorFields(_ error: Swift.Error) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.errorCode(errorCode(for: error)),
            OpalDiagnostics.Field.errorType(error),
            OpalDiagnostics.Field.errorMessage(String(describing: error))
        ]
    }
}
