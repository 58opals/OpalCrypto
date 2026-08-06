// OpalCrypto.Signature.BIP340+AuxiliaryRandomness.swift

import Foundation

extension OpalCrypto.Signature.BIP340 {
    /// Exactly 32 bytes of caller-supplied BIP340 signing randomness.
    public struct AuxiliaryRandomness: Sendable, Equatable,
        CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw 32-byte representation.
        ///
        /// Treat these bytes as secret signing-time material and never include
        /// them in logs or diagnostics.
        public let rawRepresentation: Data

        /// Validates caller-supplied BIP340 auxiliary randomness.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidAuxiliaryRandomnessLength(
                    expected: 32,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// A redacted description that never includes randomness bytes.
        public var description: String {
            "OpalCrypto.Signature.BIP340.AuxiliaryRandomness(redacted, byteCount: 32)"
        }

        /// A redacted debug description that never includes randomness bytes.
        public var debugDescription: String {
            description
        }
    }
}
