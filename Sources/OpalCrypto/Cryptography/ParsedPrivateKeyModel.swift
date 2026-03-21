// ParsedPrivateKeyModel.swift

import Foundation

struct ParsedPrivateKeyModel: Sendable, Equatable {
    enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
    }

    let scalar: ScalarModel
    let compressedPublicKeyData: Data
    let compressedPublicKeyFingerprintUInt32BigEndian: UInt32

    var compressedPublicKeyFingerprintData4Bytes: Data {
        Data(bigEndianUInt32: compressedPublicKeyFingerprintUInt32BigEndian)
    }

    init(privateKeyData32Bytes: Data) throws {
        let scalar: ScalarModel
        do {
            scalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parsePrivateKeyScalar(
                    privateKeyData32Bytes,
                    requireNonZero: true
                )
        } catch StandardsForEfficientCryptography256k1CurveModel.Operation
            .Error.invalidPrivateKeyLength(let actual) {
            throw Error.invalidPrivateKeyLength(actual: actual)
        } catch {
            throw Error.invalidPrivateKey
        }

        try self.init(trustedScalar: scalar)
    }

    init(trustedScalar: ScalarModel) throws {
        let compressedPublicKeyData = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKey(fromPrivateKeyScalar: trustedScalar)
        self.scalar = trustedScalar
        self.compressedPublicKeyData = compressedPublicKeyData
        self.compressedPublicKeyFingerprintUInt32BigEndian = SecureHash160Model
            .hash(compressedPublicKeyData)
            .uint32BigEndian(at: 0)
    }
}
