// CommunicationBoxModel~Validation.swift

import Foundation

extension CommunicationBoxModel {
    static var minimumCiphertextLength: Int {
        33 + 16 + 16
    }

    static func validateCompressedPublicKey(_ publicKey: Data) throws {
        guard publicKey.count == 33 else {
            throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
        }
        guard let prefix = publicKey.first else {
            throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
        }
        guard prefix == 0x02 || prefix == 0x03 else {
            throw Error.invalidPublicKeyPrefix(actual: prefix)
        }
    }

    static func validateSecp256k1PublicKey(_ publicKey: Data) throws {
        guard publicKey.count == 33 || publicKey.count == 65 else {
            throw Error.invalidPublicKeyLength(
                expected: expectedSecp256k1PublicKeyLength(for: publicKey),
                actual: publicKey.count
            )
        }
        guard let prefix = publicKey.first else {
            throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
        }

        let isValidPrefix = switch publicKey.count {
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

    static func expectedSecp256k1PublicKeyLength(for publicKey: Data) -> Int {
        guard let prefix = publicKey.first else {
            return 33
        }

        switch prefix {
        case 0x04:
            return 65
        case 0x02, 0x03:
            return 33
        default:
            return publicKey.count > 33 ? 65 : 33
        }
    }

    static func validatePrivateKey(_ privateKey: Data) throws {
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Operation.parsePrivateKeyScalar(
                privateKey,
                requireNonZero: true
            )
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyLength(let actual) {
            throw Error.invalidPrivateKeyLength(actual: actual)
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyValue {
            throw Error.invalidPrivateKey
        } catch {
            throw Error.cryptographyFailure
        }
    }

    static func deriveSharedSecret(
        privateKey: Data,
        publicKey: Data
    ) throws -> Data {
        try validateSecp256k1PublicKey(publicKey)
        do {
            return try StandardsForEfficientCryptography256k1CurveModel.Operation
                .deriveSharedSecret(
                    privateKeyData32Bytes: privateKey,
                    publicKey: publicKey
                )
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyLength(let actual) {
            throw Error.invalidPrivateKeyLength(actual: actual)
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPrivateKeyValue {
            throw Error.invalidPrivateKey
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPublicKeyLength(let actual) {
            throw Error.invalidPublicKeyLength(expected: 33, actual: actual)
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation.Error.invalidPublicKeyValue {
            throw Error.invalidPublicKey
        } catch {
            throw Error.cryptographyFailure
        }
    }
}
