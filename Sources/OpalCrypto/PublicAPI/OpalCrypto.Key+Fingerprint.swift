// OpalCrypto.Key+Fingerprint.swift

import Foundation

extension OpalCrypto.Key {
    /// A four-byte hierarchical deterministic key fingerprint.
    public struct Fingerprint: Sendable, Equatable {
        /// The four fingerprint bytes in big-endian order.
        public let rawRepresentation: Data

        /// Creates a fingerprint from exactly four bytes.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 4 else {
            throw ExtendedPrivate.Error.invalidParentFingerprintLength(
                    expected: 4,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
