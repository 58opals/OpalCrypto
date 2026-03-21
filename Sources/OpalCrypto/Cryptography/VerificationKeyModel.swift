// VerificationKeyModel.swift

import Foundation

struct VerificationKeyModel: Sendable, Equatable {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }

    let compressedPublicKeyData: Data
    let affinePoint: AffinePointModel
    let oddMultiplesAffine: InlineArray<8, AffinePointModel>
    let endomorphismOddMultiplesAffine: InlineArray<8, AffinePointModel>

    init(publicKeyData: Data) throws {
        let affinePoint: AffinePointModel
        do {
            affinePoint = try PublicKeyParserModel.parsePublicKey(publicKeyData)
        } catch PublicKeyParserModel.Error.invalidLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch PublicKeyParserModel.Error.invalidPrefix(let byte) {
            throw Error.invalidPublicKeyPrefix(actual: byte)
        } catch {
            throw Error.invalidPublicKey
        }

        self.init(affinePoint: affinePoint)
    }

    init(affinePoint: AffinePointModel) {
        let compressedPublicKeyData = affinePoint.encodeCompressed33()
        self.init(
            affinePoint: affinePoint,
            compressedPublicKeyData: compressedPublicKeyData
        )
    }

    init(
        affinePoint: AffinePointModel,
        compressedPublicKeyData: Data
    ) {
        self.compressedPublicKeyData = compressedPublicKeyData
        self.affinePoint = affinePoint
        self.oddMultiplesAffine = ScalarMultiplicationModel.makeOddMultiplesAffineTable(
            for: affinePoint
        )
        self.endomorphismOddMultiplesAffine = ScalarMultiplicationModel
            .makeOddMultiplesAffineTable(
                for: affinePoint.applyEndomorphism()
            )
    }

    static func == (
        lhs: VerificationKeyModel,
        rhs: VerificationKeyModel
    ) -> Bool {
        lhs.compressedPublicKeyData == rhs.compressedPublicKeyData
    }
}
