// PublicAPINumericValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API numeric validation")
struct PublicAPINumericValidator {
    @Test("Expose explicit big-endian numeric representations")
    func exposeExplicitBigEndianNumericRepresentations() throws {
        let bigInteger = OpalCrypto.Numeric.BigUnsignedInteger(
            bigEndianRepresentation: Data([0x00, 0x01, 0x02])
        )
        let fixedWidthBytes = Data(repeating: 0, count: 30) + Data([0x01, 0x02])
        let fixedWidthInteger = try OpalCrypto.Numeric.UInt256(
            bigEndianRepresentation: fixedWidthBytes
        )

        #expect(bigInteger.bigEndianRepresentation == Data([0x01, 0x02]))
        #expect(bigInteger.serialize() == bigInteger.bigEndianRepresentation)
        #expect(OpalCrypto.Numeric.BigUnsignedInteger.zero.bigEndianRepresentation.isEmpty)
        #expect(fixedWidthInteger.bigEndianRepresentation == fixedWidthBytes)
        #expect(fixedWidthInteger.bytes32 == fixedWidthInteger.bigEndianRepresentation)
    }

    @Test("Reject BigUnsignedInteger division by zero")
    func rejectBigUnsignedIntegerDivisionByZero() {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(256)

        do {
            _ = try value.divide(by: 0)
            Issue.record("Expected invalid divisor error.")
        } catch let error as OpalCrypto.Numeric.Error {
            #expect(error == .invalidDivisor(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Divide BigUnsignedInteger by a 64-bit divisor without truncating wide intermediates")
    func divideBigUnsignedIntegerByA64BitDivisorWithoutTruncatingWideIntermediates() throws {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(
            Data([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        )
        let remainder = try value.divide(by: 0x0000_0001_0000_0001)

        #expect(value.serialize() == Data([0xFF, 0xFF, 0xFF, 0xFF]))
        #expect(remainder == 1)
    }

    @Test("Division preserves quotient and remainder identity across word boundaries")
    func preserveDivisionIdentityAcrossWordBoundaries() throws {
        let inputs: [(bytes: [UInt8], divisor: UInt64)] = [
            ([], 58),
            ([0x01], 1),
            ([0x01], UInt64.max),
            ([0xFF, 0xFF, 0xFF, 0xFF], 58),
            ([0x01, 0x00, 0x00, 0x00, 0x00], UInt64(UInt32.max)),
            ([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], UInt64.max),
            ([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10],
             0x0000_0001_0000_0001),
            (Array(repeating: 0xFF, count: 64), 32)
        ]

        for input in inputs {
            let original = OpalCrypto.Numeric.BigUnsignedInteger(Data(input.bytes))
            var quotient = original
            let remainder = try quotient.divide(by: input.divisor)
            var reconstructed = quotient
            reconstructed.multiply(by: input.divisor)
            reconstructed.add(remainder)

            #expect(remainder < input.divisor)
            #expect(reconstructed == original)
        }
    }

    @Test("Add a wide UInt64 into BigUnsignedInteger without trapping intermediate overflow")
    func addWideUInt64IntoBigUnsignedIntegerWithoutTrappingIntermediateOverflow() {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0xFF, 0xFF, 0xFF, 0xFF]))
        value.add(UInt64.max)

        #expect(value.serialize() == Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE
        ]))
    }

    @Test("Multiply BigUnsignedInteger by a large 64-bit multiplier at the overflow boundary")
    func multiplyBigUnsignedIntegerByLarge64BitMultiplierAtTheOverflowBoundary() {
        var value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0xFF, 0xFF, 0xFF, 0xFF]))
        value.multiply(by: 4_294_967_298)

        #expect(value.serialize() == Data([
            0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE
        ]))
    }

    @Test("Oversized BigUnsignedInteger byte shifts avoid integer conversion traps")
    func oversizedBigUnsignedIntegerByteShiftsAvoidIntegerConversionTraps() {
        let oversizedByteCount = UInt(Int.max) + 1
        let value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0x01, 0x02, 0x03]))

        #expect(value.shiftRight(byBytes: oversizedByteCount).isZero)
    }

    @Test("Throw when a nonzero BigUnsignedInteger left shift cannot be represented")
    func throwWhenBigUnsignedIntegerLeftShiftCannotBeRepresented() throws {
        let oversizedByteCount = UInt.max
        let value = OpalCrypto.Numeric.BigUnsignedInteger(1)

        #expect(
            throws: OpalCrypto.Numeric.BigUnsignedInteger.LeftShiftError.exceedsRepresentableSize(
                byteCount: oversizedByteCount
            )
        ) {
            _ = try value.shiftedLeft(
                byBytes: oversizedByteCount,
                maximumResultByteCount: UInt.max
            )
        }
        #expect(
            try OpalCrypto.Numeric.BigUnsignedInteger.zero
                .shiftedLeft(
                    byBytes: oversizedByteCount,
                    maximumResultByteCount: 0
                )
                .isZero
        )
    }

    @Test("Allow a BigUnsignedInteger left shift at the exact result-byte budget")
    func allowBigUnsignedIntegerLeftShiftAtExactResultByteBudget() throws {
        let value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0x01, 0x02, 0x03]))

        let shiftedValue = try value.shiftedLeft(
            byBytes: 2,
            maximumResultByteCount: 5
        )

        #expect(shiftedValue.bigEndianRepresentation == Data([0x01, 0x02, 0x03, 0x00, 0x00]))
    }

    @Test("Reject a BigUnsignedInteger left shift beyond the result-byte budget")
    func rejectBigUnsignedIntegerLeftShiftBeyondResultByteBudget() {
        let value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0x01, 0x02, 0x03]))

        #expect(
            throws: OpalCrypto.Numeric.BigUnsignedInteger.LeftShiftError
                .exceedsMaximumResultByteCount(
                    requiredByteCount: 5,
                    maximumResultByteCount: 4
                )
        ) {
            _ = try value.shiftedLeft(
                byBytes: 2,
                maximumResultByteCount: 4
            )
        }
    }

    @Test(
        "BigUnsignedInteger left shifts preserve ordinary output and reject oversized output",
        arguments: BigUnsignedIntegerLeftShiftCase.allCases
    )
    func preserveOrdinaryBigUnsignedIntegerLeftShiftOutputAndRejectOversizedOutput(
        testCase: BigUnsignedIntegerLeftShiftCase
    ) throws {
        let value = OpalCrypto.Numeric.BigUnsignedInteger(Data(testCase.inputBytes))

        if let expectedBytes = testCase.expectedBytes {
            let shiftedValue = try value.shiftedLeft(
                byBytes: testCase.shiftByteCount,
                maximumResultByteCount: testCase.maximumResultByteCount
            )
            #expect(shiftedValue.serialize() == Data(expectedBytes))
        } else {
            #expect(throws: OpalCrypto.Numeric.BigUnsignedInteger.LeftShiftError.self) {
                _ = try value.shiftedLeft(
                    byBytes: testCase.shiftByteCount,
                    maximumResultByteCount: testCase.maximumResultByteCount
                )
            }
        }
    }

}
