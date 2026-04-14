// OpalCrypto.Numeric+UInt256.swift

import Foundation

extension OpalCrypto.Numeric {
    public struct UInt256: Sendable, Equatable {
        internal let rawValue: Unsigned256BitIntegerModel

        public init(data32Bytes: Data) throws {
            do {
                self.rawValue = try Unsigned256BitIntegerModel(data32Bytes: data32Bytes)
            } catch {
                throw Error.invalidDataLength(expected: 32, actual: data32Bytes.count)
            }
        }

        public var bytes32: Data {
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

        public func isBitSet(at index: Int) -> Bool {
            rawValue.isBitSet(at: index)
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
}
