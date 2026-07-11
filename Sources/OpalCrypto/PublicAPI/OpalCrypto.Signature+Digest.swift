// OpalCrypto.Signature+Digest.swift

import Foundation

extension OpalCrypto.Signature {
    /// An already computed 32-byte message digest for signature operations.
    public struct Digest: Sendable, Equatable {
        /// The 32 digest bytes.
        public let rawRepresentation: Data

        /// Creates a digest from exactly 32 bytes without hashing them again.
        ///
        /// - Throws: ``OpalCrypto/Signature/Error/invalidDigestLength(expected:actual:)`` when the input is not 32 bytes.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidDigestLength(expected: 32, actual: rawRepresentation.count)
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
