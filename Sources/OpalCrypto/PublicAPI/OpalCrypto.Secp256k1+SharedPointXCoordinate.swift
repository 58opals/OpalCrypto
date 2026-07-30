// OpalCrypto.Secp256k1+SharedPointXCoordinate.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    /// The 32-byte x-coordinate of a secp256k1 shared point.
    ///
    /// This value preserves the shared-point representation so a consuming
    /// protocol can define its own domain separation and hashing. It is
    /// secret-bearing and must not be logged or included in diagnostics.
    public struct SharedPointXCoordinate:
        Sendable,
        Equatable,
        CustomStringConvertible,
        CustomDebugStringConvertible
    {
        /// The big-endian 32-byte affine x-coordinate.
        ///
        /// This value is secret-bearing and must not be logged or included in
        /// diagnostics.
        public let rawRepresentation: Data

        /// A redacted description that never includes shared-point bytes.
        public var description: String {
            "OpalCrypto.Secp256k1.SharedPointXCoordinate(redacted, curve: secp256k1, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes shared-point bytes.
        public var debugDescription: String {
            description
        }

        internal init(validatedRawRepresentation: Data) {
            precondition(validatedRawRepresentation.count == 32)
            rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
