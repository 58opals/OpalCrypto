// OpalCrypto.KeyDerivation+DerivedKey.swift

import Foundation

extension OpalCrypto.KeyDerivation {
    /// Output from a key-derivation operation.
    ///
    /// `DerivedKey` is secret-bearing material unless the caller has explicitly derived a public value. Treat raw bytes as secret by default.
    public struct DerivedKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw derived key bytes.
        ///
        /// This value is secret-bearing and must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Creates a derived key from raw bytes.
        public init(rawRepresentation: Data) throws {
            guard !rawRepresentation.isEmpty else {
                throw Error.invalidDerivedKeyLength(actual: rawRepresentation.count)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// A redacted description that never includes derived-key bytes.
        public var description: String {
            "OpalCrypto.KeyDerivation.DerivedKey(redacted, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes derived-key bytes.
        public var debugDescription: String {
            description
        }
    }
}
