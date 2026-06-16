// OpalDiagnostics.Level+OpalCrypto.swift

import OpalDiagnostics

extension OpalDiagnostics.Level {
    static func opalCryptoDefault(for event: OpalDiagnostics.Event) -> OpalDiagnostics.Level {
        event.rawValue.hasSuffix(".failed") ? .error : .debug
    }
}
