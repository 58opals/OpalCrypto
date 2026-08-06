// HardenedScalarArithmeticModel.swift

import Foundation

/// Fixed-schedule scalar arithmetic for operations that retain private-key
/// material behind an opaque capability.
enum HardenedScalarArithmeticModel {
    static func reduceData32BytesModuloCurveOrder(
        _ data: Data
    ) -> ScalarModel {
        precondition(data.count == 32)
        guard let value = try? Unsigned256BitIntegerModel(
            contiguousBytes32: data
        ) else {
            preconditionFailure("A 32-byte value must parse as UInt256.")
        }
        let subtraction = subtractLimbs(
            value.limbs,
            StandardsForEfficientCryptography256k1CurveModel.Constant.n.limbs
        )
        let useReducedValue = subtraction.borrow ^ 1
        return ScalarModel(
            unchecked: Unsigned256BitIntegerModel(
                limbs: selectLimbs(
                    value.limbs,
                    subtraction.value,
                    bit: useReducedValue
                )
            )
        )
    }

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
        return ScalarModel(
            unchecked: Unsigned256BitIntegerModel(
                limbs: selectLimbs(
                    addition.value,
                    subtraction.value,
                    bit: useReducedValue
                )
            )
        )
    }

    static func multiplyModuloCurveOrder(
        _ left: ScalarModel,
        _ right: ScalarModel
    ) -> ScalarModel {
        var product = ScalarModel.zero
        var addend = left
        for bitIndex in 0..<256 {
            let sum = addModN(product, addend)
            let limbIndex = bitIndex / 64
            let limbBitIndex = bitIndex % 64
            let bit = (right.limbs[limbIndex] >> limbBitIndex) & 1
            product = select(product, sum, bit: bit)
            addend = addModN(addend, addend)
        }
        return product
    }

    static func negateModuloCurveOrder(
        _ scalar: ScalarModel
    ) -> ScalarModel {
        let negated = subtractLimbs(
            StandardsForEfficientCryptography256k1CurveModel.Constant.n.limbs,
            scalar.limbs
        ).value
        let combined =
            scalar.limbs[0]
            | scalar.limbs[1]
            | scalar.limbs[2]
            | scalar.limbs[3]
        let isNonzero = (combined | (UInt64.zero &- combined)) >> 63
        return ScalarModel(
            unchecked: Unsigned256BitIntegerModel(
                limbs: selectLimbs(
                    .init(repeating: 0),
                    negated,
                    bit: isNonzero
                )
            )
        )
    }

    private static func select(
        _ zeroValue: ScalarModel,
        _ oneValue: ScalarModel,
        bit: UInt64
    ) -> ScalarModel {
        ScalarModel(
            unchecked: Unsigned256BitIntegerModel(
                limbs: selectLimbs(
                    zeroValue.limbs,
                    oneValue.limbs,
                    bit: bit
                )
            )
        )
    }

    private static func selectLimbs(
        _ zeroValue: InlineArray<4, UInt64>,
        _ oneValue: InlineArray<4, UInt64>,
        bit: UInt64
    ) -> InlineArray<4, UInt64> {
        let mask = UInt64.zero &- (bit & 1)
        var selected: InlineArray<4, UInt64> = .init(repeating: 0)
        for index in 0..<4 {
            selected[index] =
                (zeroValue[index] & ~mask)
                | (oneValue[index] & mask)
        }
        return selected
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
