// StandardsForEfficientCryptography256k1CurveModel.Operation+CompressedPublicKeyChunkResult.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    struct CompressedPublicKeyChunkResult: Sendable {
        let chunkIndex: Int
        let compressedPublicKeys: [Data]
    }
}
