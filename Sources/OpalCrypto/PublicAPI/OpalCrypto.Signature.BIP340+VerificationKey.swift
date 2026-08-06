// OpalCrypto.Signature.BIP340+VerificationKey.swift

import Foundation

extension OpalCrypto.Signature.BIP340 {
    /// A validated 32-byte BIP340 x-only secp256k1 verification key.
    public struct VerificationKey: Sendable, Equatable {
        internal let verificationKeyModel:
            BitcoinImprovementProposal340VerificationKeyModel

        /// The canonical 32-byte x-only representation.
        public var rawRepresentation: Data {
            verificationKeyModel.rawRepresentationData32Bytes
        }

        /// Validates an x-only key and selects its even-Y secp256k1 point.
        ///
        /// - Throws: ``Error/invalidVerificationKeyLength(expected:actual:)`` when the representation is not 32 bytes, or ``Error/invalidVerificationKey`` when the x-coordinate does not lift to a secp256k1 point.
        public init(rawRepresentation: Data) throws {
            do {
                verificationKeyModel = try
                    BitcoinImprovementProposal340VerificationKeyModel(
                        rawRepresentationData32Bytes: rawRepresentation
                    )
            } catch BitcoinImprovementProposal340VerificationKeyModel
                .Error.invalidLength(let actual) {
                throw Error.invalidVerificationKeyLength(
                    expected: 32,
                    actual: actual
                )
            } catch {
                throw Error.invalidVerificationKey
            }
        }

        internal init(
            verificationKeyModel:
                BitcoinImprovementProposal340VerificationKeyModel
        ) {
            self.verificationKeyModel = verificationKeyModel
        }
    }
}
