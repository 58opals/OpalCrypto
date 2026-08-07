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
            (value: UInt64(6), modulus: UInt64(15), inverse: nil)
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

    private func integer(_ value: UInt64) -> RSABSSAInteger {
        var bigEndianValue = value.bigEndian
        return withUnsafeBytes(of: &bigEndianValue) {
            RSABSSAInteger(bigEndianRepresentation: Data($0))
        }
    }
}
