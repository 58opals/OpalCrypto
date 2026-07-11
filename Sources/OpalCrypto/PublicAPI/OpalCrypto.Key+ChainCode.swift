// OpalCrypto.Key+ChainCode.swift

import Foundation

extension OpalCrypto.Key {
    /// A 32-byte hierarchical deterministic key chain code.
    public struct ChainCode: Sendable, Equatable {
        /// The 32 chain-code bytes.
        public let rawRepresentation: Data

        /// Creates a chain code from exactly 32 bytes.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
            throw ExtendedPrivate.Error.invalidChainCodeLength(
                    expected: 32,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
