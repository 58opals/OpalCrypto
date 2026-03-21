// VerificationKeyModel.swift

import Foundation

struct VerificationKeyModel: Sendable, Equatable {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }

    let parsedPublicKeyModel: ParsedPublicKeyModel
    let oddMultiplesAffine: InlineArray<8, AffinePointModel>
    let endomorphismOddMultiplesAffine: InlineArray<8, AffinePointModel>

    var compressedPublicKeyData: Data {
        parsedPublicKeyModel.compressedPublicKeyData
    }

    var affinePoint: AffinePointModel {
        parsedPublicKeyModel.affinePoint
    }

    var fingerprintData4Bytes: Data {
        parsedPublicKeyModel.fingerprintData4Bytes
    }

    init(publicKeyData: Data) throws {
        do {
            self.init(parsedPublicKeyModel: try ParsedPublicKeyModel(publicKeyData: publicKeyData))
        } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
            throw Error.invalidPublicKeyPrefix(actual: actual)
        } catch {
            throw Error.invalidPublicKey
        }
    }

    init(affinePoint: AffinePointModel) {
        self.init(
            parsedPublicKeyModel: ParsedPublicKeyModel(affinePoint: affinePoint)
        )
    }

    init(parsedPublicKeyModel: ParsedPublicKeyModel) {
        self.parsedPublicKeyModel = parsedPublicKeyModel
        self.oddMultiplesAffine = ScalarMultiplicationModel.makeOddMultiplesAffineTable(
            for: parsedPublicKeyModel.affinePoint
        )
        self.endomorphismOddMultiplesAffine = ScalarMultiplicationModel
            .makeOddMultiplesAffineTable(
                for: parsedPublicKeyModel.affinePoint.applyEndomorphism()
            )
    }

    static func == (
        lhs: VerificationKeyModel,
        rhs: VerificationKeyModel
    ) -> Bool {
        lhs.parsedPublicKeyModel == rhs.parsedPublicKeyModel
    }
}
