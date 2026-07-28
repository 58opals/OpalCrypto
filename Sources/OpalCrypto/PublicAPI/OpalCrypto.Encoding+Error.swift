// OpalCrypto.Encoding+Error.swift

import Foundation

extension OpalCrypto.Encoding {
    /// An error reported by a validating encoding operation.
    public enum Error: Swift.Error, Equatable {
        /// A raw value is outside the Base32 five-bit range `0...31`.
        case invalidFiveBitValue(actual: UInt8)
        /// Base32 input contains an invalid character or mixes letter case.
        case invalidCharacterFound
        /// The requested decoded-byte limit is negative.
        case invalidMaximumDecodedByteCount(actual: Int)
        /// Decoding would produce more bytes than the caller-provided limit.
        case decodedDataExceedsMaximumByteCount(maximum: Int)
    }
}
