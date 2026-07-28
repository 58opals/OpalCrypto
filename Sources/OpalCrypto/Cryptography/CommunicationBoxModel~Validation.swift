// CommunicationBoxModel~Validation.swift

import Foundation

extension CommunicationBoxModel {
    static let ciphertextEnvelopeOverheadByteCount = 33 + 16
    static let minimumCiphertextLength = ciphertextEnvelopeOverheadByteCount + 16

    static func validateCiphertextEnvelope(
        _ ciphertext: Data,
        maximumCiphertextByteCount: Int
    ) throws {
        try validateCiphertextByteCount(
            ciphertext.count,
            maximumCiphertextByteCount: maximumCiphertextByteCount
        )
        guard ciphertext.count >= minimumCiphertextLength else {
            throw Error.invalidCiphertext
        }

        let ephemeralPublicKey = Data(ciphertext.prefix(33))
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parsePublicKeyAffine(ephemeralPublicKey)
        } catch {
            throw Error.invalidCiphertext
        }

        let encryptedPayload = ciphertext.dropFirst(33).dropLast(16)
        guard !encryptedPayload.isEmpty, encryptedPayload.count.isMultiple(of: 16) else {
            throw Error.invalidCiphertext
        }
    }

    static func validateCiphertextByteCount(
        _ ciphertextByteCount: Int,
        maximumCiphertextByteCount: Int
    ) throws {
        guard ciphertextByteCount <= maximumCiphertextByteCount else {
            throw Error.ciphertextByteCountExceedsMaximum(
                maximum: maximumCiphertextByteCount,
                actual: ciphertextByteCount
            )
        }
    }

    static func validateSecp256k1PublicKey(_ publicKey: Data) throws {
        guard let prefix = publicKey.first else {
            throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
        }

        switch prefix {
        case 0x02, 0x03:
            guard publicKey.count == 33 else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKey.count)
            }
        case 0x04:
            guard publicKey.count == 65 else {
                throw Error.invalidPublicKeyLength(expected: 65, actual: publicKey.count)
            }
        default:
            guard publicKey.count == 33 || publicKey.count == 65 else {
                throw Error.invalidPublicKeyLength(
                    expected: PublicKeyParserModel.expectedSec1PublicKeyLength(for: publicKey),
                    actual: publicKey.count
                )
            }
            throw Error.invalidPublicKeyPrefix(actual: prefix)
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
