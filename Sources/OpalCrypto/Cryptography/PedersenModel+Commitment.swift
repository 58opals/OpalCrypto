// PedersenModel+Commitment.swift

import Foundation

extension PedersenModel {
    struct Commitment: Sendable, Equatable {
        let setupIdentifier: Data
        let nonceScalar: ScalarModel
        let affinePoint: AffinePointModel

        var nonceData: Data {
            nonceScalar.data32Bytes
        }

        var compressedPointData: Data {
            affinePoint.encodeCompressed33()
        }

        var uncompressedPointData: Data {
            affinePoint.encodeUncompressed65()
        }
    }
}
