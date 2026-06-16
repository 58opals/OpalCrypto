// OpalCrypto.Pedersen.Setup~PointCombination.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen.Setup {
    public static func addPoints(
        _ points: [OpalCrypto.Pedersen.CommitmentPoint]
    ) throws -> OpalCrypto.Pedersen.CommitmentPoint {
        let fields = [
            OpalDiagnostics.Field.operationField("combine_points"),
            OpalDiagnostics.Field.publicField("point_count", points.count)
        ]
        do {
            let point = try PedersenModel.Setup.addPoints(
                points.map(\.rawRepresentation)
            )
            let commitmentPoint = try OpalCrypto.Pedersen.CommitmentPoint(validatingRawRepresentation: point)
            recordCombineSucceeded(
                outputByteCount: commitmentPoint.rawRepresentation.count,
                fields: fields
            )
            return commitmentPoint
        } catch let error as PedersenModel.Error {
            let mappedError = mapError(error)
            recordCombineFailed(mappedError, fields: fields)
            throw mappedError
        } catch let error as OpalCrypto.Pedersen.Error {
            recordCombineFailed(error, fields: fields)
            throw error
        }
    }
}
