// HardenedScalarMultiplicationModel.swift

import Foundation

/// Fixed-schedule variable-point multiplication for secret scalars.
///
/// Security invariant:
/// - exactly 256 rounds execute;
/// - every round performs one complete doubling and one complete addition;
/// - the scalar bit is consumed only by mask-based point selection;
/// - no secret-indexed table, scalar splitting, or wNAF representation is used.
///
/// The dedicated hardened field and complete projective point models preserve
/// that invariant below this orchestration layer.
enum HardenedScalarMultiplicationModel {
    static func multiply(
        _ scalar: ScalarModel,
        by point: AffinePointModel
    ) -> CompleteProjectivePointModel {
        let addend = CompleteProjectivePointModel(affinePoint: point)
        var result = CompleteProjectivePointModel.infinity

        for bitIndex in stride(from: 255, through: 0, by: -1) {
            let doubled = result.double()
            let added = doubled.add(addend)
            let scalarLimbIndex = bitIndex / 64
            let scalarLimbBitIndex = bitIndex % 64
            let bit =
                (scalar.limbs[scalarLimbIndex] >> scalarLimbBitIndex) & 1
            result = CompleteProjectivePointModel.select(
                doubled,
                added,
                bit: bit
            )
        }

        return result
    }

    static func deriveAffineXCoordinateData32Bytes(
        scalar: ScalarModel,
        point: AffinePointModel
    ) -> Data {
        multiply(scalar, by: point).affineXCoordinateData32Bytes
    }
}
