// OpalCrypto.AuthenticatedEncryption.AES256GCM+Nonce.swift

import Foundation

extension OpalCrypto.AuthenticatedEncryption.AES256GCM {
    /// A 96-bit AES-GCM nonce.
    public struct Nonce: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw nonce bytes.
        public let rawRepresentation: Data

        /// Validates caller-supplied nonce bytes.
        ///
        /// Never reuse one nonce with the same key.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count
                    == OpalCrypto.AuthenticatedEncryption.AES256GCM.nonceByteCount else {
                throw Error.invalidNonceLength(
                    expected: OpalCrypto.AuthenticatedEncryption.AES256GCM.nonceByteCount,
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
                        count: OpalCrypto.AuthenticatedEncryption.AES256GCM.nonceByteCount
                    )
                )
            } catch {
                throw Error.randomGenerationFailed
            }
        }

        /// A redacted description that never includes nonce bytes.
        public var description: String {
            "OpalCrypto.AuthenticatedEncryption.AES256GCM.Nonce(redacted, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes nonce bytes.
        public var debugDescription: String {
            description
        }
    }
}
