// PedersenModel+Commitment.swift

import Foundation

extension PedersenModel {
    struct Commitment: Sendable, Equatable {
        let setupIdentifier: Data
        let nonceScalar: ScalarModel
        let affinePoint: AffinePointModel

        var uncompressedPointData: Data {
            affinePoint.encodeUncompressed65()
        }
    }
}
