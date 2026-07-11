// OpalCrypto.Secp256k1~Diagnostics.swift

import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    static func recordKeyOperationFailed(
        _ event: OpalDiagnostics.Event,
        error: Swift.Error,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
            event: event,
            level: .opalCryptoDefault(for: event),
            fields: fields + OpalDiagnostics.Field.errorFields(error)
        )
    }
}
