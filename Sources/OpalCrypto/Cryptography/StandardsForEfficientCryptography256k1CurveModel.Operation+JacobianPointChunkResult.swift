// StandardsForEfficientCryptography256k1CurveModel.Operation+JacobianPointChunkResult.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    struct JacobianPointChunkResult: Sendable {
        let chunkIndex: Int
        let jacobianPoints: [JacobianPointModel]
    }
}
