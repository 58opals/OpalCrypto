// OpalCrypto.Signature.BIP340+Error.swift

extension OpalCrypto.Signature.BIP340 {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidVerificationKeyLength(expected: Int, actual: Int)
        case invalidVerificationKey
        case invalidAuxiliaryRandomnessLength(expected: Int, actual: Int)
        case invalidSignatureLength(expected: Int, actual: Int)
        case invalidSignature
        case signingFailed
    }
}
