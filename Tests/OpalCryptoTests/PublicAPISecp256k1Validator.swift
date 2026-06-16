// PublicAPISecp256k1Validator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API secp256k1 validation")
struct PublicAPISecp256k1Validator {
    let generatorPublicKeyHex = """
    0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    """

    func makePrivateKey(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}
