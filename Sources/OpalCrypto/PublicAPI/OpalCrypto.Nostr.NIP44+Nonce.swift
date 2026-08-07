// OpalCrypto.Nostr.NIP44+Nonce.swift

import Foundation

extension OpalCrypto.Nostr.NIP44 {
    /// A 32-byte NIP-44 version 2 message nonce.
    public struct Nonce: Sendable, Equatable,
        CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw nonce bytes.
        public let rawRepresentation: Data

        /// Validates caller-supplied nonce bytes.
        ///
        /// Never reuse one nonce with the same conversation key.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidNonceLength(
                    expected: 32,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// Generates a nonce using the operating system's secure random source.
        public static func generate() throws -> Self {
            do {
                return try Self(
                    rawRepresentation: OpalCrypto.SecureRandom.makeBytes(
                        count: 32
                    )
                )
            } catch {
                throw Error.randomGenerationFailed
            }
        }

        /// A redacted description that never includes nonce bytes.
        public var description: String {
            "OpalCrypto.Nostr.NIP44.Nonce(redacted, byteCount: 32)"
        }

        /// A redacted debug description that never includes nonce bytes.
        public var debugDescription: String {
            description
        }
    }
}
