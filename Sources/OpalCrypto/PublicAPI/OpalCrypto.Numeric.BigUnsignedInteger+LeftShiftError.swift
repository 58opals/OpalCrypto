// OpalCrypto.Numeric.BigUnsignedInteger+LeftShiftError.swift

extension OpalCrypto.Numeric.BigUnsignedInteger {
    /// An error reported by a checked left shift.
    public enum LeftShiftError: Swift.Error, Equatable {
        /// The nonzero result cannot fit in an in-memory byte buffer.
        case exceedsRepresentableSize(byteCount: UInt)

        /// The nonzero result exceeds the caller's byte budget.
        case exceedsMaximumResultByteCount(
            requiredByteCount: UInt,
            maximumResultByteCount: UInt
        )
    }
}
