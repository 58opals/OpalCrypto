// OpalDiagnostics.Category~OpalCrypto.swift

import OpalDiagnostics

extension OpalDiagnostics.Category {
    static let signature = OpalDiagnostics.Category(rawValue: "crypto.signature")
    static let key = OpalDiagnostics.Category(rawValue: "crypto.key")
    static let keyDerivation = OpalDiagnostics.Category(rawValue: "crypto.key_derivation")
    static let encoding = OpalDiagnostics.Category(rawValue: "crypto.encoding")
    static let communication = OpalDiagnostics.Category(rawValue: "crypto.communication")
    static let blindSignature = OpalDiagnostics.Category(rawValue: "crypto.blind_signature")
    static let pedersen = OpalDiagnostics.Category(rawValue: "crypto.pedersen")
    static let hashing = OpalDiagnostics.Category(rawValue: "crypto.hashing")
}
