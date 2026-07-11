// OpalCrypto.Encoding+FiveBitValues.swift

import Foundation

extension OpalCrypto.Encoding {
    /// A sequence of Base32 symbol values constrained to `0...31`.
    public struct FiveBitValues: Sendable, Equatable {
        /// The validated five-bit values, stored one per byte.
        public let rawRepresentation: Data

        /// Validates raw Base32 symbol values.
        ///
        /// - Throws: ``OpalCrypto/Encoding/Error/invalidFiveBitValue(actual:)`` at the first value greater than 31.
        public init(rawRepresentation: Data) throws {
            if let invalidValue = rawRepresentation.first(where: { $0 > 31 }) {
                throw Error.invalidFiveBitValue(actual: invalidValue)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
