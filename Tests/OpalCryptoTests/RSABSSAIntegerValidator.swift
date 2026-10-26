// RSABSSAIntegerValidator.swift

import Foundation
@testable import OpalCrypto
import Testing

@Suite("RSABSSA public-modulus arithmetic")
struct RSABSSAIntegerValidator {
    @Test(
        "Compute modular products",
        arguments: [
            (left: UInt64(7), right: UInt64(8), modulus: UInt64(11), expected: UInt64(1)),
            (left: UInt64(123_456), right: UInt64(654_321), modulus: UInt64(1_000_003), expected: UInt64(611_039)),
            (left: UInt64.max - 1, right: UInt64.max - 2, modulus: UInt64.max, expected: UInt64(2))
        ]
    )
    func computeModularProducts(
        testCase: (left: UInt64, right: UInt64, modulus: UInt64, expected: UInt64)
    ) {
        let left = integer(testCase.left)
        let right = integer(testCase.right)
        let modulus = integer(testCase.modulus)

        #expect(
            left.multipliedModulo(right, modulus: modulus)
                == integer(testCase.expected)
        )
    }

    @Test(
        "Compute modular inverses and reject non-coprime values",
        arguments: [
            (value: UInt64(3), modulus: UInt64(11), inverse: UInt64(4)),
            (value: UInt64(10), modulus: UInt64(17), inverse: UInt64(12)),
            (value: UInt64(6), modulus: UInt64(15), inverse: nil),
            (value: UInt64(0), modulus: UInt64(11), inverse: nil),
            (value: UInt64(1), modulus: UInt64(0), inverse: nil),
            (value: UInt64(1), modulus: UInt64(1), inverse: nil),
            (value: UInt64(1), modulus: UInt64(2), inverse: nil),
            (value: UInt64(3), modulus: UInt64(3), inverse: nil),
            (value: UInt64(4), modulus: UInt64(3), inverse: nil)
        ]
    )
    func computeModularInverses(
        testCase: (value: UInt64, modulus: UInt64, inverse: UInt64?)
    ) {
        let result = integer(testCase.value).inverseModulo(
            integer(testCase.modulus)
        )
        if let expected = testCase.inverse {
            #expect(result == integer(expected))
        } else {
            #expect(result == nil)
        }
    }

    @Test("Match native inverses for every small odd modulus")
    func matchSmallOddModulusInverses() {
        for modulus in stride(from: UInt64(1), through: UInt64(255), by: 2) {
            for value in UInt64(0) ... modulus {
                // Native bounded arithmetic is independent of the limb kernel.
                let expected: UInt64? = value > 0 && value < modulus
                    ? (UInt64(1) ..< modulus).first {
                        (value * $0) % modulus == 1
                    }
                    : nil
                #expect(
                    integer(value).inverseModulo(integer(modulus))
                        == expected.map(integer),
                    "value \(value), modulus \(modulus)"
                )
            }
        }
    }

    @Test("Preserve inverse carries and non-units across limb boundaries")
    func preserveCrossLimbInverseBoundaries() {
        for bitCount in [31, 32, 33, 63, 64, 65, 127, 128, 129, 2_048, 4_096] {
            var modulusBytes = Data(repeating: 0xFF, count: (bitCount + 7) / 8)
            if bitCount % 8 != 0 {
                modulusBytes[0] = UInt8((1 << (bitCount % 8)) - 1)
            }
            let modulus = RSABSSAInteger(bigEndianRepresentation: modulusBytes)

            // For m = 2^k - 1, inverse(2) = 2^(k - 1). The coefficient
            // halving step must retain the extra carry above an all-one limb.
            #expect(
                integer(2).inverseModulo(modulus) == powerOfTwo(bitCount - 1),
                "bit count \(bitCount)"
            )

            modulusBytes[modulusBytes.count - 1] = 0xFE
            let minusOne = RSABSSAInteger(bigEndianRepresentation: modulusBytes)
            #expect(minusOne.inverseModulo(modulus) == minusOne)

            // 3 divides 2^k - 1 for even k; the GCD must reach a non-unit.
            if bitCount.isMultiple(of: 2) {
                #expect(integer(3).inverseModulo(modulus) == nil)
            }
        }
    }

    @Test("Match the functional inverse on dense multi-limb operands")
    func matchDenseMultiLimbInverses() {
        for byteCount in [4, 5, 8, 9, 16, 17, 256, 512] {
            let modulus = RSABSSAInteger(
                bigEndianRepresentation: Data(repeating: 0xFF, count: byteCount)
            )
            var valueBytes = Data((0 ..< byteCount).map {
                UInt8(truncatingIfNeeded: $0 * 73 + 19)
            })
            valueBytes[valueBytes.count - 1] |= 1
            let value = RSABSSAInteger(bigEndianRepresentation: valueBytes)
            let actual = value.inverseModulo(modulus)
            #expect(actual == functionalInverse(value, modulus: modulus))
            if let actual {
                #expect(value.multipliedModulo(actual, modulus: modulus) == .one)
            }
        }
    }

    // Retain the functional arithmetic path as a differential oracle for the
    // buffer mutation. These allocating operations do not call its new helpers.
    private func functionalInverse(
        _ value: RSABSSAInteger,
        modulus: RSABSSAInteger
    ) -> RSABSSAInteger? {
        guard !value.isZero, value < modulus, !modulus.isZero, !modulus.isEven else {
            return nil
        }
        var left = value
        var right = modulus
        var leftCoefficient = RSABSSAInteger.one
        var rightCoefficient = RSABSSAInteger.zero
        while !left.isOne && !right.isOne {
            guard !left.isZero, !right.isZero else { return nil }
            while !left.isZero && left.isEven {
                left = left.shiftedRightOneBit()
                leftCoefficient = halved(leftCoefficient, modulus: modulus)
            }
            while !right.isZero && right.isEven {
                right = right.shiftedRightOneBit()
                rightCoefficient = halved(rightCoefficient, modulus: modulus)
            }
            guard !left.isZero, !right.isZero else { return nil }
            if left >= right {
                left = left.subtracting(right)
                leftCoefficient = difference(
                    leftCoefficient,
                    rightCoefficient,
                    modulus: modulus
                )
            } else {
                right = right.subtracting(left)
                rightCoefficient = difference(
                    rightCoefficient,
                    leftCoefficient,
                    modulus: modulus
                )
            }
        }
        return left.isOne ? leftCoefficient : rightCoefficient
    }

    private func halved(
        _ value: RSABSSAInteger,
        modulus: RSABSSAInteger
    ) -> RSABSSAInteger {
        value.isEven
            ? value.shiftedRightOneBit()
            : value.adding(modulus).shiftedRightOneBit()
    }

    private func difference(
        _ left: RSABSSAInteger,
        _ right: RSABSSAInteger,
        modulus: RSABSSAInteger
    ) -> RSABSSAInteger {
        left >= right
            ? left.subtracting(right)
            : modulus.subtracting(right.subtracting(left))
    }

    private func powerOfTwo(_ exponent: Int) -> RSABSSAInteger {
        var bytes = Data(repeating: 0, count: exponent / 8 + 1)
        bytes[0] = UInt8(1 << (exponent % 8))
        return RSABSSAInteger(bigEndianRepresentation: bytes)
    }

    private func integer(_ value: UInt64) -> RSABSSAInteger {
        var bigEndianValue = value.bigEndian
        return withUnsafeBytes(of: &bigEndianValue) {
            RSABSSAInteger(bigEndianRepresentation: Data($0))
        }
    }
}
