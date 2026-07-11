// OpalCrypto.Pedersen+Setup.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen {
    /// A Pedersen commitment setup bound to an alternate secp256k1 base point.
    public struct Setup: Sendable, Equatable {
        internal let setupModel: PedersenModel.Setup

        /// Creates a setup from a validated public key.
        ///
        /// - Throws: ``OpalCrypto/Pedersen/Error/insecureAlternateBasePoint`` when the alternate point equals the standard generator or produces an invalid combined point.
        public init(alternateBasePoint: OpalCrypto.Secp256k1.PublicKey) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("setup"),
                OpalDiagnostics.Field.publicField("alternate_base_point_byte_count", alternateBasePoint.rawRepresentation.count)
            ]
            do {
                setupModel = try PedersenModel.Setup(
                    alternateBasePointModel: alternateBasePoint.parsedPublicKeyModel
                )
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenSetupFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenSetupFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenSetupSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenSetupSucceeded),
                fields: fields
            )
        }

        /// Creates a commitment for `amount`, generating a secure nonce when one is not supplied.
        public func commit(
            amount: Int64,
            nonce: Nonce? = nil
        ) throws -> Commitment {
            let fields = Self.commitFields(nonce: nonce)
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.commit(
                        amount: amount,
                        nonceScalar: nonce?.scalarModel
                    )
                )
                Self.recordCommitSucceeded(
                    commitment: commitment,
                    fields: fields
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                Self.recordCommitFailed(mappedError, fields: fields)
                throw mappedError
            }
        }

        /// Returns whether `commitment` opens to `amount` with `nonce` under this setup.
        public func verify(
            commitment: CommitmentPoint,
            amount: Int64,
            nonce: Nonce
        ) throws -> Bool {
            let fields = [
                OpalDiagnostics.Field.operationField("verify"),
                OpalDiagnostics.Field.publicField("commitment_byte_count", commitment.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("nonce_byte_count", nonce.rawRepresentation.count)
            ]
            do {
                let result = try setupModel.verify(
                    commitmentAffinePoint: commitment.affinePoint,
                    amount: amount,
                    nonceScalar: nonce.scalarModel
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: result
                        ? OpalDiagnostics.Event.pedersenVerifySucceeded
                        : OpalDiagnostics.Event.pedersenVerifyFailed,
                    level: .opalCryptoDefault(for: result
                        ? OpalDiagnostics.Event.pedersenVerifySucceeded
                        : OpalDiagnostics.Event.pedersenVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenVerifyFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        /// Combines commitments created by this setup while preserving their summed nonce.
        ///
        /// - Throws: ``OpalCrypto/Pedersen/Error/emptyCommitmentList`` for an empty input or ``OpalCrypto/Pedersen/Error/mismatchedSetup`` when inputs belong to another setup.
        public func combine(
            _ commitments: [Commitment]
        ) throws -> Commitment {
            let fields = [
                OpalDiagnostics.Field.operationField("combine"),
                OpalDiagnostics.Field.publicField("commitment_count", commitments.count)
            ]
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.combine(
                        commitments.map(\.commitmentModel)
                    )
                )
                Self.recordCombineSucceeded(
                    outputByteCount: commitment.point.rawRepresentation.count,
                    fields: fields
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                Self.recordCombineFailed(mappedError, fields: fields)
                throw mappedError
            }
        }

    }
}
