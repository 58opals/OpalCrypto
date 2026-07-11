// OpalCrypto.Signature.Schnorr.VerificationBatch+Error.swift

extension OpalCrypto.Signature.Schnorr.VerificationBatch {
    /// Errors produced while constructing or executing a verification batch.
    public enum Error: Swift.Error, Sendable, Equatable {
        /// The signature and digest collections have different counts.
        case mismatchedSignatureAndDigestCounts(signatures: Int, digests: Int)

        /// The public-key collection does not contain one key per signature.
        case mismatchedPublicKeyCount(expected: Int, actual: Int)

        /// The explicitly requested execution policy is unavailable.
        case executionUnavailable(policy: OpalCrypto.BatchExecutionPolicy)

        /// The selected backend could not complete the batch.
        case executionFailed(policy: OpalCrypto.BatchExecutionPolicy)
    }
}
