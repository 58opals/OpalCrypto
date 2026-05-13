// OpalCrypto.Secp256k1+SharedSecret.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct SharedSecret: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidDerivedKey
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
