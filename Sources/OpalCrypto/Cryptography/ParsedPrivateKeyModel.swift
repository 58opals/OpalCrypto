// ParsedPrivateKeyModel.swift

import Foundation

struct ParsedPrivateKeyModel: Sendable, Equatable {
    enum Error: Swift.Error, Equatable {
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
    }

    let scalar: ScalarModel
    let parsedPublicKeyModel: ParsedPublicKeyModel

    var compressedPublicKeyData: Data {
        parsedPublicKeyModel.compressedPublicKeyData
    }

    var compressedPublicKeyFingerprintUInt32BigEndian: UInt32 {
        parsedPublicKeyModel.fingerprintUInt32BigEndian
    }

    var compressedPublicKeyFingerprintData4Bytes: Data {
        parsedPublicKeyModel.fingerprintData4Bytes
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
        let publicPoint = ScalarMultiplicationModel.mulG(trustedScalar)
        guard let publicAffine = publicPoint.convertToAffine() else {
            throw Error.invalidPrivateKey
        }
        self.scalar = trustedScalar
        self.parsedPublicKeyModel = ParsedPublicKeyModel(affinePoint: publicAffine)
    }
}
