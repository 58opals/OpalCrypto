// OpalCrypto.Key+Seed.swift

import Foundation

extension OpalCrypto.Key {
    public struct Seed: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard (16...64).contains(rawRepresentation.count) else {
                throw ExtendedPrivate.Error.invalidSeedLength(actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
