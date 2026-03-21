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
    @usableFromInline static let squareRootExponentNibbles = makeExponentNibbles(
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
    @usableFromInline static let legendreExponentNibbles = makeExponentNibbles(
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
    @usableFromInline static let inversionExponentNibbles = makeExponentNibbles(
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
        return stride(from: mostSignificantBit, through: 0, by: -1).map { exponent.isBitSet(at: $0) }
    }

    @usableFromInline static func makeExponentNibbles(
        from exponent: Unsigned256BitIntegerModel
    ) -> [UInt8] {
        var exponentNibbles: [UInt8] = .init()
        exponentNibbles.reserveCapacity(64)
        var foundNonZeroNibble = false

        for byte in exponent.data32 {
            let upperNibble = byte >> 4
            if foundNonZeroNibble || upperNibble != 0 {
                exponentNibbles.append(upperNibble)
                foundNonZeroNibble = true
            }

            let lowerNibble = byte & 0x0f
            if foundNonZeroNibble || lowerNibble != 0 {
                exponentNibbles.append(lowerNibble)
                foundNonZeroNibble = true
            }
        }

        return foundNonZeroNibble ? exponentNibbles : [0]
    }
}
