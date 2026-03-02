import Foundation

extension OpalCryptoFacade {
    public enum Numeric {
        public struct UInt256: Sendable, Equatable {
            internal let rawValue: Unsigned256BitIntegerModel

            public init(data32Bytes: Data) throws {
                do {
                    self.rawValue = try Unsigned256BitIntegerModel(data32Bytes: data32Bytes)
                } catch {
                    throw Error.invalidDataLength(expected: 32, actual: data32Bytes.count)
                }
            }

            public var data32Bytes: Data {
                rawValue.data32Bytes
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            public var isOne: Bool {
                rawValue.isOne
            }

            public var isLeastSignificantBitSet: Bool {
                rawValue.isLeastSignificantBitSet
            }

            public var mostSignificantBitIndex: Int? {
                rawValue.mostSignificantBitIndex
            }

            public func testBit(at index: Int) -> Bool {
                rawValue.testBit(at: index)
            }

            public func compare(to other: UInt256) -> ComparisonResult {
                rawValue.compare(to: other.rawValue)
            }

            public func add(_ other: UInt256) -> (sum: UInt256, carry: Bool) {
                let result = rawValue.add(other.rawValue)
                return (UInt256(rawValue: result.sum), result.carry)
            }

            public func subtract(_ other: UInt256) -> (difference: UInt256, borrow: Bool) {
                let result = rawValue.subtract(other.rawValue)
                return (UInt256(rawValue: result.difference), result.borrow)
            }

            public func multiplyFullWidth(by other: UInt256) -> UInt512 {
                UInt512(rawValue: rawValue.multiplyFullWidth(by: other.rawValue))
            }

            public func squareFullWidth() -> UInt512 {
                UInt512(rawValue: rawValue.squareFullWidth())
            }

            public func shiftRightOneBit() -> UInt256 {
                UInt256(rawValue: rawValue.shiftRightOneBit())
            }

            public mutating func shiftRightOneBitInPlace() {
                var value = rawValue
                value.shiftRightOneBitInPlace()
                self = UInt256(rawValue: value)
            }

            public func subtractWord(_ value: UInt64) -> UInt256 {
                UInt256(rawValue: rawValue.subtractWord(value))
            }

            public mutating func subtractWordInPlace(_ value: UInt64) {
                var number = rawValue
                number.subtractWordInPlace(value)
                self = UInt256(rawValue: number)
            }

            public func addWord(_ value: UInt64) -> UInt256 {
                UInt256(rawValue: rawValue.addWord(value))
            }

            public mutating func addWordInPlace(_ value: UInt64) {
                var number = rawValue
                number.addWordInPlace(value)
                self = UInt256(rawValue: number)
            }

            internal init(rawValue: Unsigned256BitIntegerModel) {
                self.rawValue = rawValue
            }
        }

        public struct UInt512: Sendable, Equatable {
            internal let rawValue: Unsigned512BitIntegerModel

            public init(data64Bytes: Data) throws {
                do {
                    self.rawValue = try Unsigned512BitIntegerModel(data64Bytes: data64Bytes)
                } catch {
                    throw Error.invalidDataLength(expected: 64, actual: data64Bytes.count)
                }
            }

            public var data64Bytes: Data {
                rawValue.data64Bytes
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            internal init(rawValue: Unsigned512BitIntegerModel) {
                self.rawValue = rawValue
            }
        }

        public struct BigUnsignedInteger: Comparable, Sendable {
            internal var rawValue: LargeUnsignedIntegerArithmeticModel

            public static let zero = BigUnsignedInteger(rawValue: .zero)

            public init(_ value: UInt64) {
                self.rawValue = LargeUnsignedIntegerArithmeticModel(value)
            }

            public init(_ data: Data) {
                self.rawValue = LargeUnsignedIntegerArithmeticModel(data)
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            public func serialize() -> Data {
                rawValue.serialize()
            }

            public func shiftLeft(by bits: Int) -> BigUnsignedInteger {
                BigUnsignedInteger(rawValue: rawValue.shiftLeft(by: bits))
            }

            public func shiftRight(by bits: Int) -> BigUnsignedInteger {
                BigUnsignedInteger(rawValue: rawValue.shiftRight(by: bits))
            }

            public mutating func add(_ addend: Int) {
                rawValue.add(addend)
            }

            public mutating func multiply(by multiplier: Int) {
                rawValue.multiply(by: multiplier)
            }

            public mutating func divide(by divisor: Int) -> Int {
                rawValue.divide(by: divisor)
            }

            public static func < (lhs: BigUnsignedInteger, rhs: BigUnsignedInteger) -> Bool {
                lhs.rawValue < rhs.rawValue
            }

            internal init(rawValue: LargeUnsignedIntegerArithmeticModel) {
                self.rawValue = rawValue
            }
        }

        public enum Error: Swift.Error, Equatable {
            case invalidDataLength(expected: Int, actual: Int)
        }
    }
}
