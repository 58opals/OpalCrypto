// OpalCrypto.Signature~Validation.swift

import Foundation

extension OpalCrypto.Signature {
    static func validatePrivateKeyLength(_ privateKeyData: Data) throws {
        guard privateKeyData.count == 32 else {
            throw Error.invalidPrivateKeyLength(expected: 32, actual: privateKeyData.count)
        }
    }

    static func validateSecp256k1PublicKey(_ publicKeyData: Data) throws {
        guard publicKeyData.count == 33 || publicKeyData.count == 65 else {
            throw Error.invalidPublicKeyLength(
                expected: expectedSecp256k1PublicKeyLength(for: publicKeyData),
                actual: publicKeyData.count
            )
        }
        guard let prefix = publicKeyData.first else {
            throw Error.invalidPublicKeyLength(expected: 33, actual: 0)
        }
        let isValidPrefix = switch publicKeyData.count {
        case 33:
            prefix == 0x02 || prefix == 0x03
        case 65:
            prefix == 0x04
        default:
            false
        }
        guard isValidPrefix else {
            throw Error.invalidPublicKeyPrefix(actual: prefix)
        }
    }

    static func expectedSecp256k1PublicKeyLength(for publicKeyData: Data) -> Int {
        guard let prefix = publicKeyData.first else {
            return 33
        }

        switch prefix {
        case 0x04:
            return 65
        case 0x02, 0x03:
            return 33
        default:
            return publicKeyData.count > 33 ? 65 : 33
        }
    }

    static func validateSchnorrDigestLength(_ digestData: Data) throws {
        guard digestData.count == 32 else {
            throw Error.invalidDigestLength(expected: 32, actual: digestData.count)
        }
    }

    static func validateECDSASignatureLength(
        _ signatureData: Data,
        format: ECDSAFormat
    ) throws {
        guard format != .raw || signatureData.count == 64 else {
            throw Error.invalidSignatureLength(expected: 64, actual: signatureData.count)
        }
    }

    static func validateSchnorrSignatureLength(_ signatureData: Data) throws {
        guard signatureData.count == 64 else {
            throw Error.invalidSignatureLength(expected: 64, actual: signatureData.count)
        }
    }
}
