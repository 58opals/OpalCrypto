// OpalCrypto.Signature.Schnorr+VerificationBatch.swift

extension OpalCrypto.Signature.Schnorr {
    /// An immutable collection of independent Schnorr verification operations.
    ///
    /// Verification preserves input order and returns one Boolean result for
    /// each signature. This type does not perform probabilistic aggregate
    /// signature verification.
    public struct VerificationBatch: Sendable {
        internal let input: SchnorrBatchVerificationInput

        /// The number of signatures in the batch.
        public var count: Int {
            input.recordCount
        }

        /// A Boolean value that indicates whether the batch contains no signatures.
        public var isEmpty: Bool {
            count == 0
        }

        /// Creates a batch whose records share one prepared verification key.
        ///
        /// - Parameters:
        ///   - signatures: The Schnorr signatures to verify.
        ///   - digests: The corresponding 32-byte message digests.
        ///   - verificationKey: The prepared key used by every record.
        /// - Throws: ``Error/mismatchedSignatureAndDigestCounts(signatures:digests:)``
        ///   when `signatures` and `digests` have different counts.
        public init(
            signatures: [OpalCrypto.Signature.Schnorr],
            digests: [OpalCrypto.Signature.Digest],
            verificationKey: OpalCrypto.Signature.VerificationKey
        ) throws {
            try Self.validateRecordCounts(
                signatureCount: signatures.count,
                digestCount: digests.count
            )
            input = SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                verificationKey: verificationKey
            )
        }

        /// Creates a batch with one public key for each signature and digest.
        ///
        /// - Parameters:
        ///   - signatures: The Schnorr signatures to verify.
        ///   - digests: The corresponding 32-byte message digests.
        ///   - publicKeys: The corresponding secp256k1 public keys.
        /// - Throws: A deterministic count-mismatch error. Signature and digest
        ///   counts are validated before the public-key count.
        public init(
            signatures: [OpalCrypto.Signature.Schnorr],
            digests: [OpalCrypto.Signature.Digest],
            publicKeys: [OpalCrypto.Secp256k1.PublicKey]
        ) throws {
            try Self.validateRecordCounts(
                signatureCount: signatures.count,
                digestCount: digests.count
            )
            guard publicKeys.count == signatures.count else {
                throw Error.mismatchedPublicKeyCount(
                    expected: signatures.count,
                    actual: publicKeys.count
                )
            }
            input = SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                publicKeys: publicKeys
            )
        }

        /// Verifies every record independently using the selected execution policy.
        ///
        /// - Parameter policy: The required execution behavior. The default
        ///   automatically selects a qualified backend.
        /// - Returns: One validity result per record in input order.
        /// - Throws: ``Error`` when execution is unavailable or fails, or
        ///   `CancellationError` when the calling task is cancelled.
        public func verify(
            using policy: OpalCrypto.BatchExecutionPolicy = .automatic
        ) async throws -> [Bool] {
            do {
                return try await SchnorrBatchVerificationOperation.verify(
                    input: input,
                    policy: policy
                )
            } catch let error as CancellationError {
                throw error
            } catch let error as Error {
                throw error
            } catch {
                throw Error.executionFailed(policy: policy)
            }
        }

        private static func validateRecordCounts(
            signatureCount: Int,
            digestCount: Int
        ) throws {
            guard signatureCount == digestCount else {
                throw Error.mismatchedSignatureAndDigestCounts(
                    signatures: signatureCount,
                    digests: digestCount
                )
            }
        }
    }
}
