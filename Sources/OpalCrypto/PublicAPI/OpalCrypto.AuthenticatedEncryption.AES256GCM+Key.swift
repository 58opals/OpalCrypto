// OpalCrypto.AuthenticatedEncryption.AES256GCM+Key.swift

import Foundation

extension OpalCrypto.AuthenticatedEncryption.AES256GCM {
    /// An exact 256-bit AES-GCM key.
    public struct Key: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw secret-bearing key bytes.
        ///
        /// This value must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Validates raw AES-256 key material.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count
                    == OpalCrypto.AuthenticatedEncryption.AES256GCM.keyByteCount else {
                throw Error.invalidKeyLength(
                    expected: OpalCrypto.AuthenticatedEncryption.AES256GCM.keyByteCount,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// Validates an OpalCrypto-derived key as exact AES-256 key material.
        public init(derivedKey: OpalCrypto.KeyDerivation.DerivedKey) throws {
            try self.init(rawRepresentation: derivedKey.rawRepresentation)
        }

        /// A redacted description that never includes key bytes.
        public var description: String {
            "OpalCrypto.AuthenticatedEncryption.AES256GCM.Key(redacted, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes key bytes.
        public var debugDescription: String {
            description
        }
    }
}
