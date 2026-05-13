// OpalCrypto.Encoding+FiveBitValues.swift

import Foundation

extension OpalCrypto.Encoding {
    public struct FiveBitValues: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            if let invalidValue = rawRepresentation.first(where: { $0 > 31 }) {
                throw Error.invalidFiveBitValue(actual: invalidValue)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
