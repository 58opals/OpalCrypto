// StandardsForEfficientCryptography256k1CurveModel.Operation+CompressedPublicKeyChunkResult.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    struct CompressedPublicKeyChunkResult: Sendable {
        let startIndex: Int
        let compressedPublicKeys: [Data]
    }
}
