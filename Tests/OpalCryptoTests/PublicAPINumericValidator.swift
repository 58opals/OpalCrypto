// PublicAPINumericValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API numeric validation")
struct PublicAPINumericValidator {
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
        #expect(value.shiftLeft(byBytes: oversizedByteCount).isZero)
        #expect(OpalCrypto.Numeric.BigUnsignedInteger.zero.shiftLeft(byBytes: oversizedByteCount).isZero)
    }

    @Test("BigUnsignedInteger left shifts reject unrepresentable result lengths")
    func bigUnsignedIntegerLeftShiftsRejectUnrepresentableResultLengths() {
        let value = OpalCrypto.Numeric.BigUnsignedInteger(Data([0x01]))

        #expect(value.shiftLeft(byBytes: UInt(Int.max)).isZero)
    }
}
