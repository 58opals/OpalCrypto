// OpalCrypto.Key+Seed.swift

import Foundation

extension OpalCrypto.Key {
    /// Binary seed material used to create BIP-32 extended private keys.
    ///
    /// `Seed` is secret-bearing key material. Its raw representation can derive private key material and should remain behind explicit secret-access or signing/authoring boundaries.
    public struct Seed: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw seed bytes.
        ///
        /// This value is secret-bearing and must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Creates seed material from raw bytes.
        ///
        /// Valid seed lengths are 16...64 bytes. The input bytes are copied so sliced `Data` values do not retain unrelated storage.
        public init(rawRepresentation: Data) throws {
            guard (16...64).contains(rawRepresentation.count) else {
                throw ExtendedPrivate.Error.invalidSeedLength(actual: rawRepresentation.count)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// A redacted description that never includes seed bytes.
        public var description: String {
            "OpalCrypto.Key.Seed(redacted, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes seed bytes.
        public var debugDescription: String {
            description
        }
    }
}
