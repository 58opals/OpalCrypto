// ScalarPowModel.swift

import Foundation

enum ScalarPowModel {
    static let inversionExponentBits = makeExponentBits(
        from: Unsigned256BitIntegerModel(
            limbs: [
                0xbfd25e8cd036413f,
                0xbaaedce6af48a03b,
                0xfffffffffffffffe,
                0xffffffffffffffff
            ]
        )
    )

    private static func makeExponentBits(from exponent: Unsigned256BitIntegerModel) -> [Bool] {
        guard let mostSignificantBit = exponent.mostSignificantBitIndex else {
            return [false]
        }
        return stride(from: mostSignificantBit, through: 0, by: -1).map { exponent.isBitSet(at: $0) }
    }
}
