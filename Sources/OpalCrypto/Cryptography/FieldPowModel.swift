// FieldPowModel.swift

import Foundation

enum FieldPowModel {
    @usableFromInline static let squareRootExponentBits = makeExponentBits(
        from: Unsigned256BitIntegerModel(
            limbs: [
                0xffffffffbfffff0c,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x3fffffffffffffff
            ]
        )
    )

    @usableFromInline static let legendreExponentBits = makeExponentBits(
        from: Unsigned256BitIntegerModel(
            limbs: [
                0xffffffff7ffffe17,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x7fffffffffffffff
            ]
        )
    )

    @usableFromInline static let inversionExponentBits = makeExponentBits(
        from: Unsigned256BitIntegerModel(
            limbs: [
                0xfffffffefffffc2d,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff
            ]
        )
    )

    @usableFromInline static func makeExponentBits(from exponent: Unsigned256BitIntegerModel) -> [Bool] {
        guard let mostSignificantBit = exponent.mostSignificantBitIndex else {
            return [false]
        }
        return stride(from: mostSignificantBit, through: 0, by: -1).map { exponent.testBit(at: $0) }
    }
}
