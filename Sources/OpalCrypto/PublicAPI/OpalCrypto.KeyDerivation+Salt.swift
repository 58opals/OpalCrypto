// OpalCrypto.KeyDerivation+Salt.swift

import Foundation

extension OpalCrypto.KeyDerivation {
    /// A nonempty salt for password-based key derivation.
    public struct Salt: Sendable, Equatable {
        /// The salt bytes.
        public let rawRepresentation: Data

        /// Creates a salt from nonempty bytes.
        ///
        /// - Throws: ``OpalCrypto/KeyDerivation/Error/emptySalt`` when `rawRepresentation` is empty.
        public init(rawRepresentation: Data) throws {
            guard !rawRepresentation.isEmpty else {
                throw Error.emptySalt
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
