// OpalCrypto.Numeric+BigUnsignedInteger.swift

import Foundation

extension OpalCrypto.Numeric {
    public struct BigUnsignedInteger: Comparable, Sendable {
        internal var rawValue: LargeUnsignedIntegerArithmeticModel

        public static let zero = BigUnsignedInteger(rawValue: .zero)

        /// Creates a value from an unsigned 64-bit integer.
        public init(_ value: UInt64) {
            self.rawValue = LargeUnsignedIntegerArithmeticModel(value)
        }

        /// Creates a value from a big-endian byte representation.
        ///
        /// Leading zero bytes are accepted and normalized. Empty data represents zero.
        public init(_ data: Data) {
            self.init(bigEndianRepresentation: data)
        }

        /// Creates a value from a big-endian byte representation.
        ///
        /// Leading zero bytes are accepted and normalized. Empty data represents zero.
        public init(bigEndianRepresentation: Data) {
            self.rawValue = LargeUnsignedIntegerArithmeticModel(bigEndianRepresentation)
        }

        public var isZero: Bool {
            rawValue.isZero
        }

        /// The minimal big-endian representation, or empty data for zero.
        public var bigEndianRepresentation: Data {
            rawValue.serialize()
        }

        /// Returns the minimal big-endian representation, or empty data for zero.
        ///
        /// Prefer ``bigEndianRepresentation`` in new code.
        public func serialize() -> Data {
            bigEndianRepresentation
        }

        /// Returns this value shifted left by whole bytes.
        ///
        /// Shifting zero always returns zero without consuming the result-byte
        /// budget, regardless of `byteCount`.
        ///
        /// - Throws: ``OpalCrypto/Numeric/BigUnsignedInteger/LeftShiftError/exceedsRepresentableSize(byteCount:)``
        ///   when the requested nonzero result cannot fit in an in-memory `Data`
        ///   value, or
        ///   ``OpalCrypto/Numeric/BigUnsignedInteger/LeftShiftError/exceedsMaximumResultByteCount(requiredByteCount:maximumResultByteCount:)``
        ///   when it exceeds the caller's byte budget.
        public func shiftedLeft(
            byBytes byteCount: UInt,
            maximumResultByteCount: UInt
        ) throws -> BigUnsignedInteger {
            guard !rawValue.isZero else { return .zero }
            let (requiredByteCount, byteCountOverflowed) = UInt(rawValue.serializedByteCount)
                .addingReportingOverflow(byteCount)
            guard !byteCountOverflowed else {
                throw LeftShiftError.exceedsRepresentableSize(byteCount: byteCount)
            }
            guard requiredByteCount <= maximumResultByteCount else {
                throw LeftShiftError.exceedsMaximumResultByteCount(
                    requiredByteCount: requiredByteCount,
                    maximumResultByteCount: maximumResultByteCount
                )
            }
            guard requiredByteCount <= UInt(Int.max) else {
                throw LeftShiftError.exceedsRepresentableSize(byteCount: byteCount)
            }
            return BigUnsignedInteger(rawValue: rawValue.shiftLeft(byBytes: Int(byteCount)))
        }

        /// Returns this value shifted right by whole bytes.
        ///
        /// A shift at least as wide as the value returns zero.
        public func shiftRight(byBytes byteCount: UInt) -> BigUnsignedInteger {
            guard byteCount <= UInt(Int.max) else { return .zero }
            return BigUnsignedInteger(rawValue: rawValue.shiftRight(byBytes: Int(byteCount)))
        }

        /// Adds an unsigned 64-bit value in place.
        public mutating func add(_ addend: UInt64) {
            rawValue.add(addend)
        }

        /// Multiplies by an unsigned 64-bit value in place.
        public mutating func multiply(by multiplier: UInt64) {
            rawValue.multiply(by: multiplier)
        }

        /// Divides in place by an unsigned 64-bit divisor and returns the remainder.
        ///
        /// - Throws: ``OpalCrypto/Numeric/Error/invalidDivisor(actual:)`` when `divisor` is zero.
        public mutating func divide(by divisor: UInt64) throws -> UInt64 {
            guard divisor > 0 else {
                throw Error.invalidDivisor(actual: divisor)
            }
            return rawValue.divide(by: divisor)
        }

        /// Returns whether `lhs` is numerically less than `rhs`.
        public static func < (lhs: BigUnsignedInteger, rhs: BigUnsignedInteger) -> Bool {
            lhs.rawValue < rhs.rawValue
        }

        internal init(rawValue: LargeUnsignedIntegerArithmeticModel) {
            self.rawValue = rawValue
        }
    }
}
