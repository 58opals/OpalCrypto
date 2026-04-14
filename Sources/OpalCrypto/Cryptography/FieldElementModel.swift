// FieldElementModel.swift

import Foundation

struct FieldElementModel: Sendable, Equatable {
    
    @usableFromInline let value: Unsigned256BitIntegerModel
    
    @usableFromInline static let zero = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [0, 0, 0, 0]))
    @usableFromInline static let one = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [1, 0, 0, 0]))
    @usableFromInline static let two = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [2, 0, 0, 0]))
    @usableFromInline static let three = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [3, 0, 0, 0]))
    @usableFromInline static let seven = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [7, 0, 0, 0]))
    @usableFromInline static let eight = FieldElementModel(unchecked: Unsigned256BitIntegerModel(limbs: [8, 0, 0, 0]))
    
    init(value: Unsigned256BitIntegerModel) throws {
        guard value.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.p) == .orderedAscending else {
            throw Error.invalidFieldValue
        }
        self.value = value
    }
    
    init(data32: Data) throws {
        try self.init(contiguousBytes32: data32)
    }

    init<Bytes: ContiguousBytes>(contiguousBytes32 bytes: Bytes) throws {
        let parsed: Unsigned256BitIntegerModel
        do {
            parsed = try Unsigned256BitIntegerModel(contiguousBytes32: bytes)
        } catch Unsigned256BitIntegerModel.Error.invalidDataLength(let expected, let actual) {
            throw Error.invalidDataLength(expected: expected, actual: actual)
        }
        try self.init(value: parsed)
    }
    
    @inlinable
    func add(_ other: FieldElementModel) -> FieldElementModel {
        let (sum, carry) = value.add(other.value)
        var reduced = sum
        if carry || reduced.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.p) != .orderedAscending {
            reduced = reduced.subtract(StandardsForEfficientCryptography256k1CurveModel.Constant.p).difference
        }
        return FieldElementModel(unchecked: reduced)
    }
    
    @inlinable
    func sub(_ other: FieldElementModel) -> FieldElementModel {
        let (difference, borrow) = value.subtract(other.value)
        var reduced = difference
        if borrow {
            reduced = reduced.add(StandardsForEfficientCryptography256k1CurveModel.Constant.p).sum
        }
        return FieldElementModel(unchecked: reduced)
    }
    
    @inlinable
    func negate() -> FieldElementModel {
        guard !value.isZero else {
            return .zero
        }
        let difference = StandardsForEfficientCryptography256k1CurveModel.Constant.p.subtract(value).difference
        return FieldElementModel(unchecked: difference)
    }
    
    @inlinable
    func mul(_ other: FieldElementModel) -> FieldElementModel {
        let product = value.multiplyFullWidth(by: other.value)
        let reduced = FieldReductionModel.reduce(product)
        return FieldElementModel(unchecked: reduced)
    }
    
    @inlinable
    func square() -> FieldElementModel {
        let product = value.squareFullWidth()
        let reduced = FieldReductionModel.reduce(product)
        return FieldElementModel(unchecked: reduced)
    }
    
    @inlinable
    func double() -> FieldElementModel {
        add(self)
    }
    
    var isQuadraticResidue: Bool {
        isQuadraticResidueUsingNibbleExponentiation
    }
    
    @inlinable
    func sqrt() -> FieldElementModel? {
        sqrtUsingNibbleExponentiation()
    }
    
    var isZero: Bool {
        value.isZero
    }
    
    var isOdd: Bool {
        value.isLeastSignificantBitSet
    }
    
    var data32: Data {
        value.data32
    }

    var data32Bytes: Data {
        data32
    }
    
    @inlinable
    init(unchecked value: Unsigned256BitIntegerModel) {
        self.value = value
    }
}
