// ParsedPrivateKeyModel.swift

import Foundation

struct ParsedPrivateKeyModel: Sendable, Equatable {

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
        guard !trustedScalar.isZero else {
            throw Error.invalidPrivateKey
        }
        self.init(validatedPrivateKeyScalar: trustedScalar)
    }

    init(validatedPrivateKeyScalar: ScalarModel) {
        let publicPoint = ScalarMultiplicationModel.mulG(validatedPrivateKeyScalar)
        guard let publicAffine = publicPoint.convertToAffine() else {
            preconditionFailure("A validated nonzero private-key scalar must produce an affine public key.")
        }
        self.scalar = validatedPrivateKeyScalar
        self.parsedPublicKeyModel = ParsedPublicKeyModel(affinePoint: publicAffine)
    }
}
