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
    static let inversionExponentNibbles = makeExponentNibbles(
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

    private static func makeExponentNibbles(
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
