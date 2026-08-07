// OpalCrypto.Nostr.NIP44+Payload.swift

extension OpalCrypto.Nostr.NIP44 {
    /// A structurally validated, canonical base64 NIP-44 version 2 payload.
    public struct Payload: Sendable, Equatable {
        /// The canonical padded-base64 representation placed in event content.
        public let encodedRepresentation: String

        internal let maximumEncodedPayloadByteCount: Int

        /// Validates an encoded payload before retaining it.
        ///
        /// `maximumEncodedPayloadByteCount` is a caller-owned allocation limit,
        /// not a NIP-44 protocol constant.
        /// This structural validation does not authenticate a containing
        /// NIP-01 event; the caller must validate that event before decryption.
        public init(
            encodedRepresentation: String,
            maximumEncodedPayloadByteCount: Int
        ) throws {
            do {
                _ = try NostrImplementationPossibility44Model.parsePayload(
                    encodedRepresentation,
                    maximumEncodedPayloadByteCount:
                        maximumEncodedPayloadByteCount
                )
            } catch let error as NostrImplementationPossibility44Model.Error {
                throw OpalCrypto.Nostr.NIP44.mapError(error)
            }
            self.encodedRepresentation = encodedRepresentation
            self.maximumEncodedPayloadByteCount =
                maximumEncodedPayloadByteCount
        }

        internal init(validatedEncodedRepresentation: String) {
            encodedRepresentation = validatedEncodedRepresentation
            maximumEncodedPayloadByteCount =
                validatedEncodedRepresentation.utf8.count
        }

        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.encodedRepresentation == rhs.encodedRepresentation
        }
    }
}
