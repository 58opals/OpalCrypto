// PolynomialModuloChecksumModel.swift

import Foundation

internal struct PolynomialModuloChecksumModel {
    private static let generatorCoefficients: [UInt64] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470
    ]

    internal static func compute(_ values: [UInt8]) -> UInt64 {
        var checksum: UInt64 = 1
        for value in values {
            let topBits = checksum >> 35
            checksum = ((checksum & 0x07ffffffff) << 5) ^ UInt64(value)
            for (index, coefficient) in generatorCoefficients.enumerated()
                where topBits & (UInt64(1) << index) != 0 {
                checksum ^= coefficient
            }
        }
        return checksum ^ 1
    }
}
