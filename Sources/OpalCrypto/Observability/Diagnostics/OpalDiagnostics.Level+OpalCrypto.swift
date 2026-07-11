// OpalDiagnostics.Level+OpalCrypto.swift

import OpalDiagnostics

extension OpalDiagnostics.Level {
    static func opalCryptoDefault(for event: OpalDiagnostics.Event) -> OpalDiagnostics.Level {
        if event == .schnorrBatchVerifyFallback {
            return .notice
        }
        return event.rawValue.hasSuffix(".failed") ? .error : .debug
    }
}
