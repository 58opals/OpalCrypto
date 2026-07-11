// OpalCrypto.Pedersen.Setup~PointCombination.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen.Setup {
    /// Adds commitment points and returns their secp256k1 group sum.
    ///
    /// - Throws: ``OpalCrypto/Pedersen/Error/emptyCommitmentList`` when `points`
    ///   is empty or ``OpalCrypto/Pedersen/Error/invalidCommitment`` when the
    ///   sum is the point at infinity.
    public static func addPoints(
        _ points: [OpalCrypto.Pedersen.CommitmentPoint]
    ) throws -> OpalCrypto.Pedersen.CommitmentPoint {
        let fields = [
            OpalDiagnostics.Field.operationField("combine_points"),
            OpalDiagnostics.Field.publicField("point_count", points.count)
        ]
        do {
            let affinePoint = try PedersenModel.Setup.addAffinePoints(
                points.map(\.affinePoint)
            )
            let commitmentPoint = OpalCrypto.Pedersen.CommitmentPoint(
                affinePoint: affinePoint
            )
            recordCombineSucceeded(
                outputByteCount: commitmentPoint.rawRepresentation.count,
                fields: fields
            )
            return commitmentPoint
        } catch let error as PedersenModel.Error {
            let mappedError = mapError(error)
            recordCombineFailed(mappedError, fields: fields)
            throw mappedError
        }
    }
}
