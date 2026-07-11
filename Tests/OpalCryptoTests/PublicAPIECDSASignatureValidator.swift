// PublicAPIECDSASignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API ECDSA signature validation")
struct PublicAPIECDSASignatureValidator {
    func makePrivateKey(_ value: UInt8) throws -> OpalCrypto.Secp256k1.PrivateKey {
        try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
