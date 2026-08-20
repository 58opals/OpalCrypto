// OpalCrypto.AuthenticatedEncryption.AES256GCM+SealedBox.swift

import Foundation

extension OpalCrypto.AuthenticatedEncryption.AES256GCM {
    /// A 96-bit nonce followed by ciphertext and a 128-bit authentication tag.
    public struct SealedBox: Sendable, Equatable {
        /// The complete nonce-ciphertext-tag representation.
        public let combinedRepresentation: Data

        /// Validates and imports a combined AES-GCM representation.
        ///
        /// `maximumCombinedByteCount` is a caller-owned allocation boundary,
        /// not an AES-GCM protocol constant.
        public init(
            combinedRepresentation: Data,
            maximumCombinedByteCount: Int
        ) throws {
            guard maximumCombinedByteCount
                    >= OpalCrypto.AuthenticatedEncryption.AES256GCM.minimumCombinedByteCount else {
                throw Error.invalidMaximumCombinedByteCount(
                    minimum: OpalCrypto.AuthenticatedEncryption.AES256GCM.minimumCombinedByteCount,
                    actual: maximumCombinedByteCount
                )
            }
            guard combinedRepresentation.count <= maximumCombinedByteCount else {
                throw Error.combinedByteCountExceedsMaximum(
                    maximum: maximumCombinedByteCount,
                    actual: combinedRepresentation.count
                )
            }
            guard combinedRepresentation.count
                    >= OpalCrypto.AuthenticatedEncryption.AES256GCM.minimumCombinedByteCount else {
                throw Error.malformedSealedBox
            }
            do {
                try AdvancedEncryptionStandard256GaloisCounterModeModel
                    .validateCombinedRepresentation(combinedRepresentation)
            } catch {
                throw Error.malformedSealedBox
            }
            self.combinedRepresentation = Data(combinedRepresentation)
        }

        internal init(validatedCombinedRepresentation: Data) {
            combinedRepresentation = Data(validatedCombinedRepresentation)
        }
    }
}
