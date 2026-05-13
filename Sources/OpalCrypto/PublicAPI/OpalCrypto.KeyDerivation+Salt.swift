// OpalCrypto.KeyDerivation+Salt.swift

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
}
