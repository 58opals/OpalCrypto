// OpalCrypto.Numeric+BigUnsignedInteger.swift

import Foundation

extension OpalCrypto.Numeric {
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

        public func shiftLeft(byBytes byteCount: UInt) -> BigUnsignedInteger {
            guard !rawValue.isZero else { return .zero }
            guard byteCount <= UInt(Int.max) else { return .zero }
            guard byteCount <= UInt(Int.max - rawValue.serializedByteCount) else { return .zero }
            return BigUnsignedInteger(rawValue: rawValue.shiftLeft(byBytes: Int(byteCount)))
        }

        public func shiftRight(byBytes byteCount: UInt) -> BigUnsignedInteger {
            guard byteCount <= UInt(Int.max) else { return .zero }
            return BigUnsignedInteger(rawValue: rawValue.shiftRight(byBytes: Int(byteCount)))
        }

        public mutating func add(_ addend: UInt64) {
            rawValue.add(addend)
        }

        public mutating func multiply(by multiplier: UInt64) {
            rawValue.multiply(by: multiplier)
        }

        public mutating func divide(by divisor: UInt64) throws -> UInt64 {
            guard divisor > 0 else {
                throw Error.invalidDivisor(actual: divisor)
            }
            return rawValue.divide(by: divisor)
        }

        public static func < (lhs: BigUnsignedInteger, rhs: BigUnsignedInteger) -> Bool {
            lhs.rawValue < rhs.rawValue
        }

        internal init(rawValue: LargeUnsignedIntegerArithmeticModel) {
            self.rawValue = rawValue
        }
    }
}
