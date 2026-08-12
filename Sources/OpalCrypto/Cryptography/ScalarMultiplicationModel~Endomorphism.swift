// ScalarMultiplicationModel~Endomorphism.swift

import Foundation

extension ScalarMultiplicationModel {
    @inlinable
    static func addWindowedDigit(
        _ digit: Int8,
        using table: InlineArray<16, AffinePointModel>,
        to point: JacobianPointModel
    ) -> JacobianPointModel {
        guard digit != 0 else {
            return point
        }
        let isNegative = digit < 0
        let magnitude = Int(isNegative ? -digit : digit)
        let tableIndex = magnitude >> 1
        let affinePoint = table[tableIndex]
        return point.addAffine(isNegative ? affinePoint.negate() : affinePoint)
    }
}
