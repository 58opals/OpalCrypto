// HardenedFieldElementModel.swift

import Foundation

/// Field arithmetic for secret-scalar multiplication.
///
/// Every operation uses fixed loop bounds and mask-based selection. In
/// particular, reduction never exits early based on field values. Keep this
/// type separate from the general-purpose field model so a future
/// optimization cannot silently reintroduce variable-time arithmetic into the
/// hardened shared-point path.
struct HardenedFieldElementModel: Sendable {
    private static let reductionConstant: UInt64 = 0x0000_0001_0000_03D1

    private let limbs: InlineArray<4, UInt64>

    static let zero = HardenedFieldElementModel(limbs: .init(repeating: 0))
    static let one = HardenedFieldElementModel(limbs: [1, 0, 0, 0])
    static let twentyOne = HardenedFieldElementModel(
        limbs: [21, 0, 0, 0]
    )

    init(_ fieldElement: FieldElementModel) {
        limbs = fieldElement.value.limbs
    }

    private init(limbs: InlineArray<4, UInt64>) {
        self.limbs = limbs
    }

    var data32Bytes: Data {
        Unsigned256BitIntegerModel(limbs: limbs).data32Bytes
    }

    var fieldElementModel: FieldElementModel {
        FieldElementModel(
            unchecked: Unsigned256BitIntegerModel(limbs: limbs)
        )
    }

    var isZero: Bool {
        (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0
    }

    func add(_ other: HardenedFieldElementModel) -> HardenedFieldElementModel {
        let addition = Self.addLimbs(limbs, other.limbs)
        let subtraction = Self.subtractLimbs(
            addition.value,
            StandardsForEfficientCryptography256k1CurveModel.Constant.p.limbs
        )
        let useReducedValue = addition.carry | (subtraction.borrow ^ 1)
        return Self.select(
            HardenedFieldElementModel(limbs: addition.value),
            HardenedFieldElementModel(limbs: subtraction.value),
            bit: useReducedValue
        )
    }

    func sub(_ other: HardenedFieldElementModel) -> HardenedFieldElementModel {
        let subtraction = Self.subtractLimbs(limbs, other.limbs)
        let corrected = Self.addLimbs(
            subtraction.value,
            StandardsForEfficientCryptography256k1CurveModel.Constant.p.limbs
        ).value
        return Self.select(
            HardenedFieldElementModel(limbs: subtraction.value),
            HardenedFieldElementModel(limbs: corrected),
            bit: subtraction.borrow
        )
    }

    func mul(_ other: HardenedFieldElementModel) -> HardenedFieldElementModel {
        let product = Self.multiplyFullWidth(limbs, other.limbs)
        var accumulator: InlineArray<6, UInt64> = .init(repeating: 0)
        accumulator[0] = product[0]
        accumulator[1] = product[1]
        accumulator[2] = product[2]
        accumulator[3] = product[3]

        for index in 0..<4 {
            Self.addProduct(
                product[index + 4],
                Self.reductionConstant,
                at: index,
                to: &accumulator
            )
        }

        // For p = 2^256 - (2^32 + 977), each upper limb can be folded
        // back by multiplying it by the reduction constant. Three fixed
        // folds exceed the two required by the arithmetic bound and keep
        // the schedule independent of the value being reduced.
        for _ in 0..<3 {
            let limbFour = accumulator[4]
            let limbFive = accumulator[5]
            accumulator[4] = 0
            accumulator[5] = 0
            Self.addProduct(
                limbFour,
                Self.reductionConstant,
                at: 0,
                to: &accumulator
            )
            Self.addProduct(
                limbFive,
                Self.reductionConstant,
                at: 1,
                to: &accumulator
            )
        }

        let folded: InlineArray<4, UInt64> = [
            accumulator[0],
            accumulator[1],
            accumulator[2],
            accumulator[3]
        ]
        let subtraction = Self.subtractLimbs(
            folded,
            StandardsForEfficientCryptography256k1CurveModel.Constant.p.limbs
        )
        return Self.select(
            HardenedFieldElementModel(limbs: folded),
            HardenedFieldElementModel(limbs: subtraction.value),
            bit: subtraction.borrow ^ 1
        )
    }

    func square() -> HardenedFieldElementModel {
        mul(self)
    }

    func double() -> HardenedFieldElementModel {
        add(self)
    }

    func invert() -> HardenedFieldElementModel {
        let powerTwoToOneMinusOne = self
        let powerTwoToTwoMinusOne = powerTwoToOneMinusOne
            .square()
            .mul(powerTwoToOneMinusOne)
        let powerTwoToFourMinusOne = powerTwoToTwoMinusOne
            .square(2)
            .mul(powerTwoToTwoMinusOne)
        let powerTwoToSixMinusOne = powerTwoToFourMinusOne
            .square(2)
            .mul(powerTwoToTwoMinusOne)
        let powerTwoToEightMinusOne = powerTwoToFourMinusOne
            .square(4)
            .mul(powerTwoToFourMinusOne)
        let powerTwoToSixteenMinusOne = powerTwoToEightMinusOne
            .square(8)
            .mul(powerTwoToEightMinusOne)
        let powerTwoToThirtyTwoMinusOne = powerTwoToSixteenMinusOne
            .square(16)
            .mul(powerTwoToSixteenMinusOne)
        let powerTwoToSixtyFourMinusOne = powerTwoToThirtyTwoMinusOne
            .square(32)
            .mul(powerTwoToThirtyTwoMinusOne)
        let powerTwoToOneHundredTwentyEightMinusOne = powerTwoToSixtyFourMinusOne
            .square(64)
            .mul(powerTwoToSixtyFourMinusOne)
        let powerTwoToOneHundredNinetyTwoMinusOne =
            powerTwoToOneHundredTwentyEightMinusOne
                .square(64)
                .mul(powerTwoToSixtyFourMinusOne)
        let powerTwoToSevenMinusOne = powerTwoToSixMinusOne.square().mul(self)
        let powerTwoToFifteenMinusOne = powerTwoToEightMinusOne
            .square(7)
            .mul(powerTwoToSevenMinusOne)
        let powerTwoToThirtyOneMinusOne = powerTwoToSixteenMinusOne
            .square(15)
            .mul(powerTwoToFifteenMinusOne)
        let powerTwoToTwoHundredTwentyThreeMinusOne =
            powerTwoToOneHundredNinetyTwoMinusOne
                .square(31)
                .mul(powerTwoToThirtyOneMinusOne)
        let upperExponent = powerTwoToTwoHundredTwentyThreeMinusOne.square(33)

        let powerTwoToTwentyTwoMinusOne = powerTwoToSixteenMinusOne
            .square(6)
            .mul(powerTwoToSixMinusOne)
        var lowerExponent = powerTwoToTwentyTwoMinusOne.square(4)
        lowerExponent = lowerExponent.square().mul(self)
        lowerExponent = lowerExponent.square()
        lowerExponent = lowerExponent.square().mul(self)
        lowerExponent = lowerExponent.square().mul(self)
        lowerExponent = lowerExponent.square()
        lowerExponent = lowerExponent.square().mul(self)

        return upperExponent.mul(lowerExponent)
    }

    static func select(
        _ zeroValue: HardenedFieldElementModel,
        _ oneValue: HardenedFieldElementModel,
        bit: UInt64
    ) -> HardenedFieldElementModel {
        let mask = UInt64.zero &- (bit & 1)
        var selected: InlineArray<4, UInt64> = .init(repeating: 0)
        for index in 0..<4 {
            selected[index] =
                (zeroValue.limbs[index] & ~mask)
                | (oneValue.limbs[index] & mask)
        }
        return HardenedFieldElementModel(limbs: selected)
    }

    private func square(_ count: Int) -> HardenedFieldElementModel {
        var result = self
        for _ in 0..<count {
            result = result.square()
        }
        return result
    }

    private static func multiplyFullWidth(
        _ left: InlineArray<4, UInt64>,
        _ right: InlineArray<4, UInt64>
    ) -> InlineArray<8, UInt64> {
        var result: InlineArray<8, UInt64> = .init(repeating: 0)
        for leftIndex in 0..<4 {
            for rightIndex in 0..<4 {
                addProduct(
                    left[leftIndex],
                    right[rightIndex],
                    at: leftIndex + rightIndex,
                    to: &result
                )
            }
        }
        return result
    }

    private static func addProduct(
        _ left: UInt64,
        _ right: UInt64,
        at index: Int,
        to accumulator: inout InlineArray<8, UInt64>
    ) {
        let product = left.multipliedFullWidth(by: right)
        let lowAddition = addWithCarry(
            accumulator[index],
            product.low,
            carry: 0
        )
        accumulator[index] = lowAddition.value
        let highAddition = addWithCarry(
            accumulator[index + 1],
            product.high,
            carry: lowAddition.carry
        )
        accumulator[index + 1] = highAddition.value

        var carry = highAddition.carry
        for propagationIndex in (index + 2)..<8 {
            let addition = addWithCarry(
                accumulator[propagationIndex],
                0,
                carry: carry
            )
            accumulator[propagationIndex] = addition.value
            carry = addition.carry
        }
    }

    private static func addProduct(
        _ left: UInt64,
        _ right: UInt64,
        at index: Int,
        to accumulator: inout InlineArray<6, UInt64>
    ) {
        let product = left.multipliedFullWidth(by: right)
        let lowAddition = addWithCarry(
            accumulator[index],
            product.low,
            carry: 0
        )
        accumulator[index] = lowAddition.value
        let highAddition = addWithCarry(
            accumulator[index + 1],
            product.high,
            carry: lowAddition.carry
        )
        accumulator[index + 1] = highAddition.value

        var carry = highAddition.carry
        for propagationIndex in (index + 2)..<6 {
            let addition = addWithCarry(
                accumulator[propagationIndex],
                0,
                carry: carry
            )
            accumulator[propagationIndex] = addition.value
            carry = addition.carry
        }
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
