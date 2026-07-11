// SchnorrBatchVerificationInput.swift

struct SchnorrBatchVerificationInput: Sendable {
    let signatures: [OpalCrypto.Signature.Schnorr]
    let digests: [OpalCrypto.Signature.Digest]
    let keyInput: SchnorrBatchVerificationKeyInput

    var recordCount: Int {
        signatures.count
    }

    init(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) {
        self.signatures = signatures
        self.digests = digests
        self.keyInput = .cached(verificationKey)
    }

    init(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        publicKeys: [OpalCrypto.Secp256k1.PublicKey]
    ) {
        self.signatures = signatures
        self.digests = digests
        self.keyInput = .varying(publicKeys)
    }
}
