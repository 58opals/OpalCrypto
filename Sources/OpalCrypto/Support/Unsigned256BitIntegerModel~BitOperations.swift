// Unsigned256BitIntegerModel~BitOperations.swift

import Foundation

extension Unsigned256BitIntegerModel {
    @inlinable
    public func shiftRightOneBit() -> Unsigned256BitIntegerModel {
        var result = self
        result.shiftRightOneBitInPlace()
        return result
    }

    @inlinable
    public mutating func shiftRightOneBitInPlace() {
        var carry: UInt64 = 0
        for index in stride(from: 3, through: 0, by: -1) {
            let limb = limbs[index]
            let nextCarry = limb & 1
            limbs[index] = (limb >> 1) | (carry << 63)
            carry = nextCarry
        }
    }

    @inlinable
    public func subtractWord(_ value: UInt64) -> Unsigned256BitIntegerModel {
        var result = self
        result.subtractWordInPlace(value)
        return result
    }

    @inlinable
    public mutating func subtractWordInPlace(_ value: UInt64) {
        var borrow = value
        for index in 0..<4 {
            if borrow == 0 {
                break
            }
            let (difference, overflow) = limbs[index].subtractingReportingOverflow(borrow)
            limbs[index] = difference
            borrow = overflow ? 1 : 0
        }
    }

    @inlinable
    public func addWord(_ value: UInt64) -> Unsigned256BitIntegerModel {
        var result = self
        result.addWordInPlace(value)
        return result
    }

    @inlinable
    public mutating func addWordInPlace(_ value: UInt64) {
        var carry = value
        for index in 0..<4 {
            if carry == 0 {
                break
            }
            let (sum, overflow) = limbs[index].addingReportingOverflow(carry)
            limbs[index] = sum
            carry = overflow ? 1 : 0
        }
    }
}
