// OpalCrypto.KeyDerivation+DerivedKey.swift

import Foundation

extension OpalCrypto.KeyDerivation {
    public struct DerivedKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard !rawRepresentation.isEmpty else {
                throw Error.invalidDerivedKeyLength(actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
