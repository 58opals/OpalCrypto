// HardenedScalarArithmeticModel.swift

/// Fixed-schedule scalar arithmetic for operations that retain private-key
/// material behind an opaque capability.
enum HardenedScalarArithmeticModel {
    static func addModN(
        _ left: ScalarModel,
        _ right: ScalarModel
    ) -> ScalarModel {
        let addition = addLimbs(left.limbs, right.limbs)
        let subtraction = subtractLimbs(
            addition.value,
            StandardsForEfficientCryptography256k1CurveModel.Constant.n.limbs
        )
        let useReducedValue = addition.carry | (subtraction.borrow ^ 1)
        let mask = UInt64.zero &- (useReducedValue & 1)
        var selected: InlineArray<4, UInt64> = .init(repeating: 0)
        for index in 0..<4 {
            selected[index] =
                (addition.value[index] & ~mask)
                | (subtraction.value[index] & mask)
        }
        return ScalarModel(
            unchecked: Unsigned256BitIntegerModel(limbs: selected)
        )
    }

    private static func addLimbs(
        _ left: InlineArray<4, UInt64>,
        _ right: InlineArray<4, UInt64>
    ) -> (value: InlineArray<4, UInt64>, carry: UInt64) {
        var value: InlineArray<4, UInt64> = .init(repeating: 0)
        var carry: UInt64 = 0
        for index in 0..<4 {
            let addition = addWithCarry(
                left[index],
                right[index],
                carry: carry
            )
            value[index] = addition.value
            carry = addition.carry
        }
        return (value, carry)
    }

    private static func subtractLimbs(
        _ left: InlineArray<4, UInt64>,
        _ right: InlineArray<4, UInt64>
    ) -> (value: InlineArray<4, UInt64>, borrow: UInt64) {
        var value: InlineArray<4, UInt64> = .init(repeating: 0)
        var borrow: UInt64 = 0
        for index in 0..<4 {
            let subtraction = subtractWithBorrow(
                left[index],
                right[index],
                borrow: borrow
            )
            value[index] = subtraction.value
            borrow = subtraction.borrow
        }
        return (value, borrow)
    }

    private static func addWithCarry(
        _ left: UInt64,
        _ right: UInt64,
        carry: UInt64
    ) -> (value: UInt64, carry: UInt64) {
        let partialValue = left &+ right
        let partialCarry =
            ((left & right) | ((left | right) & ~partialValue)) >> 63
        let value = partialValue &+ carry
        let finalCarry =
            ((partialValue & carry) | ((partialValue | carry) & ~value)) >> 63
        return (value, partialCarry | finalCarry)
    }

    private static func subtractWithBorrow(
        _ left: UInt64,
        _ right: UInt64,
        borrow: UInt64
    ) -> (value: UInt64, borrow: UInt64) {
        let partialValue = left &- right
        let partialBorrow =
            ((~left & right) | (~(left ^ right) & partialValue)) >> 63
        let value = partialValue &- borrow
        let finalBorrow =
            ((~partialValue & borrow) | (~(partialValue ^ borrow) & value)) >> 63
        return (value, partialBorrow | finalBorrow)
    }
}
