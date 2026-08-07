// OpalCrypto.Nostr.NIP44+ConversationKey.swift

import Foundation

extension OpalCrypto.Nostr.NIP44 {
    /// A 32-byte NIP-44 conversation key.
    public struct ConversationKey: Sendable, Equatable,
        CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw secret-bearing key bytes.
        public let rawRepresentation: Data

        /// Validates an existing conversation key.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidConversationKeyLength(
                    expected: 32,
                    actual: rawRepresentation.count
                )
            }
            self.rawRepresentation = Data(rawRepresentation)
        }

        /// A redacted description that never includes key bytes.
        public var description: String {
            "OpalCrypto.Nostr.NIP44.ConversationKey(redacted, byteCount: 32)"
        }

        /// A redacted debug description that never includes key bytes.
        public var debugDescription: String {
            description
        }

        internal init(validatedRawRepresentation: Data) {
            precondition(validatedRawRepresentation.count == 32)
            rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
