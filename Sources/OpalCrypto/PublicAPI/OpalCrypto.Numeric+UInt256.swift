// OpalCrypto.Numeric+UInt256.swift

import Foundation

extension OpalCrypto.Numeric {
    public struct UInt256: Sendable, Equatable {
        internal let rawValue: Unsigned256BitIntegerModel

        /// Creates a value from exactly 32 big-endian bytes.
        ///
        /// - Throws: ``OpalCrypto/Numeric/Error/invalidDataLength(expected:actual:)`` when the representation is not 32 bytes.
        public init(data32Bytes: Data) throws {
            try self.init(bigEndianRepresentation: data32Bytes)
        }

        /// Creates a value from exactly 32 big-endian bytes.
        ///
        /// - Throws: ``OpalCrypto/Numeric/Error/invalidDataLength(expected:actual:)`` when the representation is not 32 bytes.
        public init(bigEndianRepresentation: Data) throws {
            do {
                self.rawValue = try Unsigned256BitIntegerModel(data32Bytes: bigEndianRepresentation)
            } catch {
                throw Error.invalidDataLength(expected: 32, actual: bigEndianRepresentation.count)
            }
        }

        /// The fixed-width 32-byte big-endian representation.
        public var bytes32: Data {
            bigEndianRepresentation
        }

        /// The fixed-width 32-byte big-endian representation.
        public var bigEndianRepresentation: Data {
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

        /// Returns whether the zero-based bit is set, or `false` outside `0..<256`.
        public func isBitSet(at index: Int) -> Bool {
            rawValue.isBitSet(at: index)
        }

        /// Compares this value numerically with `other`.
        public func compare(to other: UInt256) -> ComparisonResult {
            rawValue.compare(to: other.rawValue)
        }

        /// Adds two values modulo 2²⁵⁶ and reports the discarded carry bit.
        public func add(_ other: UInt256) -> (sum: UInt256, carry: Bool) {
            let result = rawValue.add(other.rawValue)
            return (UInt256(rawValue: result.sum), result.carry)
        }

        /// Subtracts two values modulo 2²⁵⁶ and reports whether the operation borrowed.
        public func subtract(_ other: UInt256) -> (difference: UInt256, borrow: Bool) {
            let result = rawValue.subtract(other.rawValue)
            return (UInt256(rawValue: result.difference), result.borrow)
        }

        /// Returns the full-width 512-bit product.
        public func multiplyFullWidth(by other: UInt256) -> UInt512 {
            UInt512(rawValue: rawValue.multiplyFullWidth(by: other.rawValue))
        }

        /// Returns the full-width 512-bit square.
        public func squareFullWidth() -> UInt512 {
            UInt512(rawValue: rawValue.squareFullWidth())
        }

        /// Returns this value shifted right by one bit.
        public func shiftRightOneBit() -> UInt256 {
            UInt256(rawValue: rawValue.shiftRightOneBit())
        }

        /// Shifts this value right by one bit in place.
        public mutating func shiftRightOneBitInPlace() {
            var value = rawValue
            value.shiftRightOneBitInPlace()
            self = UInt256(rawValue: value)
        }

        /// Subtracts a 64-bit word modulo 2²⁵⁶.
        public func subtractWord(_ value: UInt64) -> UInt256 {
            UInt256(rawValue: rawValue.subtractWord(value))
        }

        /// Subtracts a 64-bit word modulo 2²⁵⁶ in place.
        public mutating func subtractWordInPlace(_ value: UInt64) {
            var number = rawValue
            number.subtractWordInPlace(value)
            self = UInt256(rawValue: number)
        }

        /// Adds a 64-bit word modulo 2²⁵⁶.
        public func addWord(_ value: UInt64) -> UInt256 {
            UInt256(rawValue: rawValue.addWord(value))
        }

        /// Adds a 64-bit word modulo 2²⁵⁶ in place.
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
