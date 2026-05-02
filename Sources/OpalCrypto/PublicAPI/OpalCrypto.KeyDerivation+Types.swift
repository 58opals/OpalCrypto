// OpalCrypto.KeyDerivation+Types.swift

import Foundation

extension OpalCrypto.KeyDerivation {
    public struct Salt: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard !rawRepresentation.isEmpty else {
                throw Error.emptySalt
            }
            self.rawRepresentation = rawRepresentation
        }
    }

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
