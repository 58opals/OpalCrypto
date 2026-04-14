// StandardsForEfficientCryptography256k1CurveModel.swift

import Foundation

internal enum StandardsForEfficientCryptography256k1CurveModel {
    
    static let halfOrderScalar = ScalarModel(
        unchecked: Unsigned256BitIntegerModel(
            limbs: [
                0xdfe92f46681b20a0,
                0x5d576e7357a4501d,
                0xffffffffffffffff,
                0x7fffffffffffffff
            ]
        )
    )
}
