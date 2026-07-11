// SchnorrBatchVerificationKeyInput.swift

enum SchnorrBatchVerificationKeyInput: Sendable {
    case cached(OpalCrypto.Signature.VerificationKey)
    case varying([OpalCrypto.Secp256k1.PublicKey])
}
