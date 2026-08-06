// OpalCrypto.Signature+BIP340.swift

import Foundation

extension OpalCrypto.Signature {
    /// A validated 64-byte BIP340 Schnorr signature over secp256k1.
    ///
    /// This type implements BIP340's tagged hashes and even-Y x-only key
    /// semantics. It is distinct from ``Schnorr``, which remains the Bitcoin
    /// Cash Schnorr signature API.
    public struct BIP340: Sendable, Equatable {
        internal let rFieldElementModel: FieldElementModel
        internal let sScalarModel: ScalarModel

        /// The canonical 64-byte `r || s` representation.
        public var rawRepresentation: Data {
            rFieldElementModel.data32Bytes + sScalarModel.data32Bytes
        }

        /// Validates a BIP340 signature representation.
        ///
        /// - Throws: ``Error/invalidSignatureLength(expected:actual:)`` when the representation is not 64 bytes, or ``Error/invalidSignature`` when `r` is outside the secp256k1 field or `s` is outside the curve order.
        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 64 else {
                throw Error.invalidSignatureLength(
                    expected: 64,
                    actual: rawRepresentation.count
                )
            }
            do {
                rFieldElementModel = try FieldElementModel(
                    data32: Data(rawRepresentation.prefix(32))
                )
                sScalarModel = try ScalarModel(
                    data32: Data(rawRepresentation.suffix(32))
                )
            } catch {
                throw Error.invalidSignature
            }
        }

        /// Verifies this signature over an existing 32-byte digest.
        ///
        /// The digest bytes are used as BIP340's message `m`; OpalCrypto does
        /// not apply a separate prehash at this boundary.
        public func verify(
            digest: Digest,
            verificationKey: VerificationKey
        ) -> Bool {
            BitcoinImprovementProposal340SignatureModel.verify(
                signatureRFieldElement: rFieldElementModel,
                signatureSScalar: sScalarModel,
                digestData32Bytes: digest.rawRepresentation,
                verificationKeyModel:
                    verificationKey.verificationKeyModel
            )
        }

        internal init(
            rFieldElementModel: FieldElementModel,
            sScalarModel: ScalarModel
        ) {
            self.rFieldElementModel = rFieldElementModel
            self.sScalarModel = sScalarModel
        }
    }
}
