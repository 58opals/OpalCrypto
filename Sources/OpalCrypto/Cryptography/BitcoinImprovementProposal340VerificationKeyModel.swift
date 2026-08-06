// BitcoinImprovementProposal340VerificationKeyModel.swift

import Foundation

struct BitcoinImprovementProposal340VerificationKeyModel: Sendable, Equatable {
    let affinePoint: AffinePointModel
    let verificationKeyModel: VerificationKeyModel

    var rawRepresentationData32Bytes: Data {
        affinePoint.x.data32Bytes
    }

    init(rawRepresentationData32Bytes: Data) throws {
        guard rawRepresentationData32Bytes.count == 32 else {
            throw Error.invalidLength(actual: rawRepresentationData32Bytes.count)
        }
        let xCoordinate: FieldElementModel
        do {
            xCoordinate = try FieldElementModel(
                data32: rawRepresentationData32Bytes
            )
        } catch {
            throw Error.invalidPoint
        }
        let ySquared = xCoordinate.square().mul(xCoordinate).add(.seven)
        guard var yCoordinate = ySquared.sqrt() else {
            throw Error.invalidPoint
        }
        if yCoordinate.isOdd {
            yCoordinate = yCoordinate.negate()
        }
        self.init(
            affinePoint: AffinePointModel(
                x: xCoordinate,
                y: yCoordinate
            )
        )
    }

    init(affinePoint: AffinePointModel) {
        let evenYPoint = affinePoint.y.isOdd
            ? affinePoint.negate()
            : affinePoint
        self.affinePoint = evenYPoint
        self.verificationKeyModel = VerificationKeyModel(
            affinePoint: evenYPoint
        )
    }

    static func == (
        lhs: BitcoinImprovementProposal340VerificationKeyModel,
        rhs: BitcoinImprovementProposal340VerificationKeyModel
    ) -> Bool {
        lhs.rawRepresentationData32Bytes
            == rhs.rawRepresentationData32Bytes
    }
}
