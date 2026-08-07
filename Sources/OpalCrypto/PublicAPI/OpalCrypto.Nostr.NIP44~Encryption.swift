// OpalCrypto.Nostr.NIP44~Encryption.swift

extension OpalCrypto.Nostr.NIP44 {
    /// Encrypts UTF-8 text with a securely generated nonce.
    ///
    /// `maximumPlaintextByteCount` is a required caller-owned allocation
    /// boundary. It does not change the standard's wire representation.
    public static func encrypt(
        _ plaintext: String,
        conversationKey: ConversationKey,
        maximumPlaintextByteCount: Int
    ) throws -> Payload {
        try encrypt(
            plaintext,
            conversationKey: conversationKey,
            nonce: .generate(),
            maximumPlaintextByteCount: maximumPlaintextByteCount
        )
    }

    /// Encrypts UTF-8 text with an explicit 32-byte nonce.
    ///
    /// This entry point supports conformance vectors and injected secure-random
    /// dependencies. Never reuse `nonce` with the same conversation key.
    public static func encrypt(
        _ plaintext: String,
        conversationKey: ConversationKey,
        nonce: Nonce,
        maximumPlaintextByteCount: Int
    ) throws -> Payload {
        do {
            return Payload(
                validatedEncodedRepresentation:
                    try NostrImplementationPossibility44Model.encrypt(
                        plaintext: plaintext,
                        conversationKey: conversationKey.rawRepresentation,
                        nonce: nonce.rawRepresentation,
                        maximumPlaintextByteCount:
                            maximumPlaintextByteCount
                    )
            )
        } catch let error as NostrImplementationPossibility44Model.Error {
            throw mapError(error)
        }
    }

    /// Authenticates, decrypts, unpads, and UTF-8 decodes a NIP-44 payload.
    ///
    /// - Important: Before calling this method, validate the identifier,
    ///   public key, and BIP-340 signature of the NIP-01 event containing the
    ///   payload. NIP-44 requires outer-event authentication before decryption.
    public static func decrypt(
        _ payload: Payload,
        conversationKey: ConversationKey,
        maximumPlaintextByteCount: Int
    ) throws -> String {
        do {
            return try NostrImplementationPossibility44Model.decrypt(
                encodedPayload: payload.encodedRepresentation,
                conversationKey: conversationKey.rawRepresentation,
                maximumEncodedPayloadByteCount:
                    payload.maximumEncodedPayloadByteCount,
                maximumPlaintextByteCount: maximumPlaintextByteCount
            )
        } catch let error as NostrImplementationPossibility44Model.Error {
            throw mapError(error)
        }
    }
}
